mod common;

// app(socks) -> (socks)client(chain(jls+trojan)) -> (chain(jls+trojan))server(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-tls",
    feature = "outbound-trojan",
    feature = "inbound-tls",
    feature = "inbound-trojan",
    feature = "outbound-direct",
    feature = "inbound-chain",
    feature = "outbound-chain",
))]
#[test]
fn test_tls_trojan() {
    let config1 = r#"
    {
        "inbounds": [
            {
                "protocol": "socks",
                "address": "127.0.0.1",
                "port": 1086
            }
        ],
        "outbounds": [
            {
                "protocol": "chain",
                "settings": {
                    "actors": [
                        "jls",
                        "trojan"
                    ]
                }
            },
            {
                "protocol": "jls",
                "tag": "jls",
                "settings": {
                    "serverName": "codepen.io",
                    "alpn": [
                        "h2"
                    ],
                    "pwd": "user_pwd",
                    "iv": "user_iv",
                    "zeroRtt": true
                }
            },
            {
                "protocol": "trojan",
                "tag": "trojan",
                "settings": {
                    "password": "password",
                    "address": "127.0.0.1",
                    "port": 3001
                }
            }
        ]
    }
    "#;

    let config2 = r#"
    {
        "inbounds": [
            {
                "protocol": "chain",
                "address": "127.0.0.1",
                "port": 3001,
                "settings": {
                    "actors": [
                        "jls",
                        "trojan"
                    ]
                }
            },
            {
                "protocol": "jls",
                "tag": "jls",
                "settings": {
                    "certificate": "cert.pem",
                    "certificateKey": "key.pem",
                    "alpn": [
                        "h2"
                    ],
                    "upstreamUrl":"https://codepen.io:443",
                    "pwd": "user_pwd",
                    "iv": "user_iv",
                    "zeroRtt": true
                }
            },
            {
                "protocol": "trojan",
                "tag": "trojan",
                "settings": {
                    "passwords": [
                        "password"
                    ]
                }
            }
        ],
        "outbounds": [
            {
                "protocol": "direct"
            }
        ]
    }
    "#;

    let config3 = r#"
    {
        "inbounds": [
            {
                "protocol": "socks",
                "address": "127.0.0.1",
                "port": 1087
            }
        ],
        "outbounds": [
            {
                "protocol": "chain",
                "settings": {
                    "actors": [
                        "jls",
                        "trojan"
                    ]
                }
            },
            {
                "protocol": "jls",
                "tag": "jls",
                "settings": {
                    "serverName": "codepen.io",
                    "alpn": [
                        "h2"
                    ],
                    "pwd": "user_pwd",
                    "iv": "user_iv",
                    "zeroRtt": false
                }
            },
            {
                "protocol": "trojan",
                "tag": "trojan",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 3002,
                    "password": "password"
                }
            }
        ]
    }
    "#;

    let config4 = r#"
    {
        "inbounds": [
            {
                "protocol": "chain",
                "address": "127.0.0.1",
                "port": 3002,
                "settings": {
                    "actors": [
                        "jls",
                        "trojan"
                    ]
                }
            },
            {
                "protocol": "jls",
                "tag": "jls",
                "settings": {
                    "alpn": [
                        "h2"
                    ],
                    "upstreamUrl":"https://codepen.io:443",
                    "pwd": "user_pwd",
                    "iv": "user_iv",
                    "zeroRtt": false
                    
                }
            },
            {
                "protocol": "trojan",
                "tag": "trojan",
                "settings": {
                    "passwords": [
                        "password"
                    ]
                }
            }
        ],
        "outbounds": [
            {
                "protocol": "direct"
            }
        ]
    }
    "#;

    let mut path = std::env::current_exe().unwrap();
    path.pop();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(&path.join("key.der"), &cert.serialize_private_key_der()).unwrap();
    std::fs::write(&path.join("cert.der"), &cert.serialize_der().unwrap()).unwrap();
    std::fs::write(&path.join("key.pem"), &cert.serialize_private_key_pem()).unwrap();
    std::fs::write(&path.join("cert.pem"), &cert.serialize_pem().unwrap()).unwrap();
    let configs = vec![config1.to_string(), config2.to_string()];
    common::test_configs(configs, "127.0.0.1", 1086);
    let configs = vec![config3.to_string(), config4.to_string()];
    common::test_configs(configs, "127.0.0.1", 1087);
}
