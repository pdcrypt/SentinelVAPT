# Lab variant C, a regression (lab only). The Content-Security-Policy and
# X-Content-Type-Options of variant B are removed again; the version header of
# variant B stays.
add_header X-AspNet-Version "4.0.30319" always;
# Marker for lab-variant.sh and for checking with curl; no rule reads it.
add_header X-Lab-Variant "c" always;
