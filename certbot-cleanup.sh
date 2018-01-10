#!/usr/bin/env bash

if [ -z "${CERTBOT_DOMAIN}" ]; then echo "This script needs CERTBOT_DOMAIN env"; exit 1; fi
if [ -z "${CERTBOT_VALIDATION}" ]; then echo "This script needs CERTBOT_VALIDATION env"; exit 1; fi

./dynect-hook.py clean_challenge "${CERTBOT_DOMAIN}" "${CERTBOT_TOKEN}" "${CERTBOT_VALIDATION}"
