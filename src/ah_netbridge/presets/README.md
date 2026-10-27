This directory contains TaiXin-published CE/Europe, FCC/US, and MIC/Japan
channel configurations. They are convenient starting points, not legal
authorization. Read the profile warning and verify the exact module variant,
antenna, installation, application class, power, duty-cycle/channel-access
requirements, and current local rules before transmitting.

The FCC 1 MHz configuration is not included because TaiXin publishes 24
centres for it, while the managed CHAN_LIST schema safely permits at most 16.
No channels are silently discarded. Every centre must lie within
700000–1000000 kHz and be divisible by 100 kHz.

Custom presets use the same TOML format and are loaded with `--preset-dir DIR`,
which replaces this directory.
