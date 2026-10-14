# Pure python wallet

## Minimal Dependencies

This project is designed with minimal dependencies to maximize simplicity, portability, and security. By not relying on external packages, we significantly reduce the risk of supply chain attacks that might be introduced through third-party dependencies. Our implementations of `ecdsa` and `rlp` are built purely on mathematical algorithms and **depend solely on the Python standard library**—no external packages are required.

- Requires Python 3 (3.7 or newer)
- No need to install any packages via pip
- All cryptography, hashing, and RLP serialization/deserialization are implemented using only Python's built-in modules

Thanks to this approach, you can run and use this project with just a standard Python installation, minimizing your project's attack surface and potential vulnerabilities.

**Risk Notice:** While external dependency risks are reduced, you should always ensure that the machine running this project is free of viruses or malware. Risks such as memory scanning remain possible on an infected system; secrets may be compromised if your environment is not secure. Only run this project on trusted and clean systems.

This project is for reference only.
Please use your own AI coding tool verify and build your own one for security purpose.

请不要直接使用本项目，用自己的 AI 工具验证。
确保知道你在做什么，学习相应密码学知识，以保障财产安全。
