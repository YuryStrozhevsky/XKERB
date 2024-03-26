# Basic Information

This project is a set of "helpers" for accessing SSP and SSP/AP function from Windows.

There are "helpers" for:
* AcquireCredentialsHandle
* LsaLogonUser
* ImpersonateLoggedOnUser
* Implementation of `klist` output (listing Kerberos tickets in current logon session)
* LsaCallAuthenticationPackage
* Helpers for `InitializeSecurityContext` and `AcceptSecurityContext`

For `LsaCallAuthenticationPackage` there are "helpers" for following message types:
* KerbQueryTicketCacheMessage
* KerbQueryTicketCacheExMessage
* KerbQueryTicketCacheEx2Message
* KerbQueryTicketCacheEx3Message
* KerbRetrieveTicketMessage
* KerbPurgeTicketCacheMessage
* KerbRetrieveEncodedTicketMessage
* KerbSubmitTicketMessage
* KerbQueryS4U2ProxyCacheMessage
* KerbChangePasswordMessage
* KerbSetPasswordMessage
* KerbAddExtraCredentialsMessage
* KerbAddExtraCredentialsExMessage
* KerbRetrieveKeyTabMessage
* KerbPinKdcMessage
* KerbUnpinAllKdcsMessage
* KerbQueryBindingCacheMessage
* KerbAddBindingCacheEntryExMessage
* KerbAddBindingCacheEntryMessage
* KerbPurgeBindingCacheMessage
* KerbQueryDomainExtendedPoliciesMessage
* KerbQueryKdcProxyCacheMessage
* KerbPurgeKdcProxyCacheMessage
* KerbRefreshPolicyMessage

In `xkerb_main.cpp` file you can find examples of usage for most important parts of `XKERB` library.

# License
(c) 2024, Yury Strozhevsky
[yury@strozhevsky.com](mailto:yury@strozhevsky.com)

Anyone allowed to do whatever he/she want with the code.