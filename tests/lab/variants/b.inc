# Lab variant B, "remediated" (lab only). A Content-Security-Policy with
# frame-ancestors and X-Content-Type-Options are added; the X-Powered-By header
# is gone; a different version header appears (a new disclosure).
add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'none'" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-AspNet-Version "4.0.30319" always;
# Marker for lab-variant.sh and for checking with curl; no rule reads it.
add_header X-Lab-Variant "b" always;
