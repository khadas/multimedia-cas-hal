#Irdeto CAS_HAL/TA
PRODUCT_PACKAGES += \
    libird_dvb \
    ird_test

# TA
PRODUCT_PACKAGES += \
    b64fd559-658d-48a4-bbc7b95d8663f457

# persistent storage file
PRODUCT_PACKAGES += \
    cloaked_ca_1 \
    cloaked_ca_9 \
    cloaked_ca_62 \
    cloaked_ca_72

PRODUCT_PROPERTY_OVERRIDES += \
    vendor.tv.dtv.cas.type=irdeto
