
## Goals
- Sender
    - [ ] Pairing
    - [ ] Multi-room support
- Receiver? 

## Getting Started
Uses Avahi daemon for Zeroconf networking on Linux.

```bash
# This daemon will need to be running at run-time.
sudo apt-get install avahi-daemon

# Install Linux dependencies
sudo apt install xorg-dev libxcb-shape0-dev libxcb-xfixes0-dev libavahi-client-dev clang

# Run the crate:
cargo run
```

## References
- [https://9to5mac.com/2019/12/05/airplay-2-cracked/](https://9to5mac.com/2019/12/05/airplay-2-cracked/)
- [https://openairplay.github.io/airplay-spec/](https://openairplay.github.io/airplay-spec/)
- [https://emanuelecozzi.net/docs/airplay2](https://emanuelecozzi.net/docs/airplay2)
- [https://github.com/openairplay/airplay2-receiver](https://github.com/openairplay/airplay2-receiver)