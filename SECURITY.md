# Security policy

## Supported versions

Only the latest release receives fixes.

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's private reporting: on the repository's **Security** tab choose **Report a vulnerability**. Include the image version, how you ran the container (without secrets), and what you observed.

Reports that matter most for this project:

- traffic or DNS queries leaving the container outside the tunnel;
- a way around `ALLOWED_HOSTS`, `ALLOWED_PORTS` or proxy authentication;
- a profile directive that survives hardening and runs code or changes routing;
- credentials appearing in logs.

You should get a first answer within a week.
