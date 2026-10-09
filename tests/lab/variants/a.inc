# Lab variant A, the baseline (lab only, controlled headers; no real data).
# Discloses a framework version. No Content-Security-Policy, no framing
# protection, no X-Content-Type-Options. Same idea as HEADERS_A of the e2e lab
# (frontend/tests/e2e/support/lab.ts).
add_header X-Powered-By "PHP/8.1.0" always;
# Marker for lab-variant.sh and for checking with curl; no rule reads it.
add_header X-Lab-Variant "a" always;
