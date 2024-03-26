#include "index.h"

#include <iostream>
//***********************************************************************************************************
#pragma region Data necessary for testing (names/passwords etc.)
//***********************************************************************************************************
std::wstring TEST_DOMAIN{ L"DOMAIN.LAN" };
std::wstring TEST_DOMAIN_SHORT{ L"DOMAIN" };
std::wstring TEST_SERVER{ L"SERVER" }; // Name for the KDC machine

// This user represents pure "client" and does not have any SPNs
std::wstring TEST_USER_1_NAME{ L"user1" };
std::wstring TEST_USER_1_PASS{ L"password1" };

// This user represents one of "service" and need to have SPNs
// All the delegation variants must be set for this particular user
std::wstring TEST_USER_2_NAME{ L"user2" };
std::wstring TEST_USER_2_PASS{ L"password2" };
std::wstring TEST_USER_2_SPN{ L"SPN1/SPN1" };

// This user represents one of "service" and need to have SPNs
// For this "service" user #1 will delegate client's tickets
std::wstring TEST_USER_3_NAME{ L"user3" };
std::wstring TEST_USER_3_PASS{ L"password3" };
std::wstring TEST_USER_3_SPN{ L"SPN2/SPN2" };
//***********************************************************************************************************
#pragma endregion
//***********************************************************************************************************
/*
    With the function it is possible to test literaly any type of communication between "client" and "service".
    In order to have isolated environment it is useful to make separate logon sessions for both parts.
    By having such two sessions it is possible to have information about tickets etc. dispite the other's tickets.
*/
void universal_flow(
    XKERB::XLogonUserParameters ClientLogonParameters,
    XKERB::XLogonUserParameters ServiceLogonParameters,
    std::wstring_view TargetServiceName,
    std::optional<std::function<void(SECURITY_STATUS, XKERB::XClientSecurityContext*)>> ClientContextActivity = std::nullopt,
    std::optional<std::function<void(SECURITY_STATUS, XKERB::XServerSecurityContext*)>> ServerContextActivity = std::nullopt,
    std::wstring PackageName = L"Kerberos",
    ULONG ClientContextFlags = ISC_REQ_MUTUAL_AUTH | ISC_REQ_DELEGATE,
    ULONG ServiceContextFlags = ASC_REQ_EXTENDED_ERROR
)
{
    #pragma region Initial variables
    SECURITY_STATUS SecStatus;

    XKERB::CredHandleReturnType ClientCredentialsHandle;
    XKERB::CredHandleReturnType ServerCredentialsHandle;
    #pragma endregion

    try
    {
        #pragma region Initiate logon for both client and server sides
        auto ClientToken = XKERB::XLogonUser(ClientLogonParameters);
        auto ServerToken = XKERB::XLogonUser(ServiceLogonParameters);
        #pragma endregion

        #pragma region Initialize credential handle for client side
        {
            auto ImpersonateGuard = XKERB::XImpersonateLoggedOnUser(ClientToken.get());
            ClientCredentialsHandle = XKERB::XAcquireCredentialsHandle({ .CredentialsUse = SECPKG_CRED_OUTBOUND, .Package = PackageName });
        }

        // If we do not put ISC_REQ_DELEGATE here then on service side would be only a ticket to the service, not for KRBTGT
        XKERB::XClientSecurityContext ClientContext{ ClientCredentialsHandle.get(), ClientContextFlags, TargetServiceName };
        #pragma endregion

        #pragma region Initialize credential handle for server side
        {
            auto ImpersonateGuard = XKERB::XImpersonateLoggedOnUser(ServerToken.get());
            ServerCredentialsHandle = XKERB::XAcquireCredentialsHandle({ .CredentialsUse = SECPKG_CRED_INBOUND, .Package = PackageName });
        }

        XKERB::XServerSecurityContext ServerContext{ ServerCredentialsHandle.get(), ServiceContextFlags };
        #pragma endregion

        #pragma region Main loop
        do
        {
            {
                auto ImpersonateGuard = XKERB::XImpersonateLoggedOnUser(ClientToken.get());
                SecStatus = ClientContext.Process(&ServerContext.Output);

                if(ClientContextActivity)
                    ClientContextActivity.value()(SecStatus, &ClientContext);
            }

            if(SecStatus < 0)
                throw std::exception(XKERB::secstatus_to_string("Client context", SecStatus).data());

            if(!ClientContext.HasData())
                break;

            {
                auto ImpersonateGuard = XKERB::XImpersonateLoggedOnUser(ServerToken.get());
                SecStatus = ServerContext.Process(&ClientContext.Output);

                if(ServerContextActivity)
                    ServerContextActivity.value()(SecStatus, &ServerContext);
            }

            if(SecStatus < 0)
                throw std::exception(XKERB::secstatus_to_string("Service context", SecStatus).data());

            if((SEC_E_OK == SecStatus) && (!ServerContext.HasData()))
                break;

        } while(ServerContext.HasData());
        #pragma endregion
    }
    catch(std::exception ex)
    {
        std::cout << "ERROR: " << ex.what() << std::endl;
    }
    catch(...)
    {
        std::cout << "Unknown ERROR happen" << std::endl;
    }
}
//***********************************************************************************************************
void test_delegate_kerberos()
{
    XKERB::XCallAuthenticationPackage<KerbPurgeTicketCacheMessage>({});

    universal_flow(
        { 
            .User = TEST_USER_1_NAME,
            .Password = TEST_USER_1_PASS 
        },
        {
            .User = TEST_USER_2_NAME,
            .Password = TEST_USER_2_PASS
        },
        TEST_USER_2_SPN,
        [](SECURITY_STATUS status, XKERB::XClientSecurityContext* context)
        {
            std::cout << "Client tickets:" << std::endl;
            std::cout << "============================" << std::endl;
            XKERB::XKList();
            std::cout << "============================" << std::endl;
        },
        [](SECURITY_STATUS status, XKERB::XServerSecurityContext* context)
        {
            std::cout << "Server status: " << status << std::endl;
            if(status == 0)
            {
                auto guard = context->Impersonate();

                auto CredentialHandle = XKERB::XAcquireCredentialsHandle({ .CredentialsUse = SECPKG_CRED_OUTBOUND });

                XKERB::XClientSecurityContext ClientContext{ CredentialHandle.get(), ISC_REQ_MUTUAL_AUTH | ISC_REQ_DELEGATE, TEST_USER_3_SPN };

                auto status = ClientContext.Process(nullptr);

                std::cout << "Secondary service status: " << status;

                if(status < 0)
                    std::cout << " (" << XKERB::secstatus_to_string("Client context", status) << ")";

                std::cout << std::endl << std::endl;;

                std::cout << "Server tickets (impersonated):" << std::endl;
                std::cout << "============================" << std::endl;
                std::wcout << XKERB::XKList();
                std::cout << "============================" << std::endl;
            }
            else
            {
                std::cout << "Server tickets:" << std::endl;
                std::cout << "============================" << std::endl;
                std::wcout << XKERB::XKList();
                std::cout << "============================" << std::endl;
            }
        }
    );

    int iii = 0;
}
//***********************************************************************************************************
void test_add_credentials()
{
    SECURITY_STATUS SecStatus;

    XKERB::CredHandleReturnType ClientCredentialsHandle;
    XKERB::CredHandleReturnType ServerCredentialsHandle;

    auto ClientToken = XKERB::XLogonUser({ .User = TEST_USER_1_NAME, .Password = TEST_USER_1_PASS, .Domain = TEST_DOMAIN });
    auto ServerToken = XKERB::XLogonUser({ .User = TEST_USER_2_NAME, .Password = TEST_USER_2_PASS, .Domain = TEST_DOMAIN });

    {
        auto ImpersonateGuard = XKERB::XImpersonateLoggedOnUser(ClientToken.get());
        ClientCredentialsHandle = XKERB::XAcquireCredentialsHandle({
            .CredentialsUse = SECPKG_CRED_OUTBOUND
        });
    }

    // We explicitly asking for service ticket for TEST_USER_3_NAME's SPN
    XKERB::XClientSecurityContext ClientContext{ ClientCredentialsHandle.get(), ISC_REQ_MUTUAL_AUTH, TEST_USER_3_SPN };

    {
        auto ImpersonateGuard = XKERB::XImpersonateLoggedOnUser(ServerToken.get());

        // The service context is initialized by credentials for TEST_USER_2_NAME
        ServerCredentialsHandle = XKERB::XAcquireCredentialsHandle({
            .CredentialsUse = SECPKG_CRED_INBOUND
        });

        // But after we add credentials for TEST_USER_3_NAME we can handle
        // any incoming service tickets for TEST_USER_3_SPN
        XKERB::XCallAuthenticationPackage<KerbAddExtraCredentialsMessage>({
            .UserName = TEST_USER_3_NAME,
            .DomainName = TEST_DOMAIN,
            .Password = TEST_USER_3_PASS
        });
    }

    XKERB::XServerSecurityContext ServerContext{ ServerCredentialsHandle.get(), ASC_REQ_EXTENDED_ERROR };

    // Standard loop like in "universal_flow" function
    do
    {
        {
            auto ImpersonateGuard = XKERB::XImpersonateLoggedOnUser(ClientToken.get());
            SecStatus = ClientContext.Process(&ServerContext.Output);
        }

        if(SecStatus < 0)
            throw std::exception(XKERB::secstatus_to_string("Client context", SecStatus).data());

        if(!ClientContext.HasData())
            break;

        {
            auto ImpersonateGuard = XKERB::XImpersonateLoggedOnUser(ServerToken.get());
            SecStatus = ServerContext.Process(&ClientContext.Output);

            std::wcout << XKERB::XKList();

            int iii = 0;
        }

        if(SecStatus < 0)
            throw std::exception(XKERB::secstatus_to_string("Service context", SecStatus).data());

        if((SEC_E_OK == SecStatus) && (!ServerContext.HasData()))
            break;
    } while(ServerContext.HasData());
}
//***********************************************************************************************************
void test_submit_tkt()
{
    auto ClientToken = XKERB::XLogonUser({ .User = TEST_USER_1_NAME, .Password = TEST_USER_1_PASS, .Domain = TEST_DOMAIN });
    auto ServerToken = XKERB::XLogonUser({ .User = TEST_USER_2_NAME, .Password = TEST_USER_2_PASS, .Domain = TEST_DOMAIN });

    std::unique_ptr<KERB_RETRIEVE_TKT_RESPONSE, XKERB::_LsaFreeReturnBuffer> res;

    {
        auto ImpersonateGuard = XKERB::XImpersonateLoggedOnUser(ClientToken.get());

        res = XKERB::XCallAuthenticationPackage<KerbRetrieveEncodedTicketMessage>({
            .TargetName = std::format(L"ldap/{}@{}", TEST_SERVER, TEST_DOMAIN),
            .CacheOptions = KERB_RETRIEVE_TICKET_DONT_USE_CACHE | KERB_RETRIEVE_TICKET_AS_KERB_CRED
        });

        std::wcout << XKERB::XKList();
    }

    std::cout << "=============================================" << std::endl;

    {
        auto ImpersonateGuard = XKERB::XImpersonateLoggedOnUser(ServerToken.get());

        auto res2 = XKERB::XCallAuthenticationPackage<KerbSubmitTicketMessage>({
            .Ticket = std::vector<byte>{ res->Ticket.EncodedTicket, res->Ticket.EncodedTicket + res->Ticket.EncodedTicketSize }
        });

        std::wcout << XKERB::XKList();
    }
}
//***********************************************************************************************************
void test_submit_tkt_2()
{
    auto ServerToken = XKERB::XLogonUser({ .User = TEST_USER_2_NAME, .Password = TEST_USER_2_PASS, .Domain = TEST_DOMAIN });

    // Retriving ticket together with using explicit credentials handle
    auto res = XKERB::XCallAuthenticationPackage<KerbRetrieveEncodedTicketMessage>({
        .TargetName = std::format(L"ldap/{}@{}", TEST_SERVER, TEST_DOMAIN),
        .CacheOptions = KERB_RETRIEVE_TICKET_DONT_USE_CACHE | KERB_RETRIEVE_TICKET_AS_KERB_CRED,
        .CredentialsHandle = *(XKERB::XAcquireCredentialsHandle({
            .User = TEST_USER_1_NAME,
            .Password = TEST_USER_1_PASS
        }))
    });

    std::wcout << XKERB::XKList();
    std::cout << "=============================================" << std::endl;

    {
        auto ImpersonateGuard = XKERB::XImpersonateLoggedOnUser(ServerToken.get());

        auto res2 = XKERB::XCallAuthenticationPackage<KerbSubmitTicketMessage>({
            .Ticket = std::vector<byte>{ res->Ticket.EncodedTicket, res->Ticket.EncodedTicket + res->Ticket.EncodedTicketSize }
        });

        std::wcout << XKERB::XKList();
    }

    int iii = 0;
}
//***********************************************************************************************************
void test_pin_unpin_kdc()
{
    XKERB::XCallAuthenticationPackage<KerbPinKdcMessage>({
        .Realm = TEST_DOMAIN,
        .KdcAddress = L"127.127.127.127" // If port specified then no TCP/UDP at all, thus only default port 88 would be using by Kerberos
        });


    auto handle = XKERB::XAcquireCredentialsHandle({
        .User = TEST_USER_1_NAME,
        .Password = TEST_USER_1_PASS
    });

    try
    {
        // The request will fail if you are not running this on DC, of course
        auto res = XKERB::XCallAuthenticationPackage<KerbRetrieveEncodedTicketMessage>({
            .TargetName = std::format(L"ldap/{}@{}", TEST_SERVER, TEST_DOMAIN),
            .CacheOptions = KERB_RETRIEVE_TICKET_DONT_USE_CACHE,
            .CredentialsHandle = *handle
        });
    }
    catch(std::exception ex)
    {
        std::cout << "Request FAILED: " << ex.what() << std::endl;
    }

    XKERB::XCallAuthenticationPackage<KerbUnpinAllKdcsMessage>({});

    // This request will pass
    auto res = XKERB::XCallAuthenticationPackage<KerbRetrieveEncodedTicketMessage>({
        .TargetName = std::format(L"ldap/{}@{}", TEST_SERVER, TEST_DOMAIN),
        .CacheOptions = KERB_RETRIEVE_TICKET_DONT_USE_CACHE,
        .CredentialsHandle = *handle
    });
}
//***********************************************************************************************************
int main()
{
    return 0;
}
//***********************************************************************************************************
