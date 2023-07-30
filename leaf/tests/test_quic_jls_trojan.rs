mod common;

// app(socks) -> (socks)client(chain(quic-jls+trojan)) -> (chain(quic-jls+trojan))server(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-quic-jls",
    feature = "outbound-trojan",
    feature = "inbound-quic-jls",
    feature = "inbound-trojan",
    feature = "outbound-direct",
    feature = "inbound-chain",
    feature = "outbound-chain",
))]
#[test]
fn test_quic_jls_trojan() {
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
                        "quic-jls",
                        "trojan"
                    ]
                }
            },
            {
                "protocol": "quic-jls",
                "tag": "quic-jls",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 3001,
                    "serverName": "codepen.io",
                    "alpn": [
                        "h3"
                    ],
                    "pwd": "user_pwd",
                    "iv": "user_iv",
                    "zeroRtt": true,
                    "congestionController": "bbr"
                }
            },
            {
                "protocol": "trojan",
                "tag": "trojan",
                "settings": {
                    "password": "password"
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
                        "quic-jls",
                        "trojan"
                    ]
                }
            },
            {
                "protocol": "quic-jls",
                "tag": "quic-jls",
                "settings": {
                    "certificate": "cert.der",
                    "certificateKey": "key.der",
                    "alpn": [
                        "h3"
                    ],
                    "upstreamAddr":"codepen.io:443",
                    "pwd": "user_pwd",
                    "iv": "user_iv",
                    "zeroRtt": true,
                    "congestionController": "bbr"
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
                        "quic-jls",
                        "trojan"
                    ]
                }
            },
            {
                "protocol": "quic-jls",
                "tag": "quic-jls",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 3002,
                    "serverName": "codepen.io",
                    "alpn": [
                        "h3"
                    ],
                    "pwd": "user_pwd",
                    "iv": "user_iv",
                    "zeroRtt": false,
                    "congestionController": "bbr"
                }
            },
            {
                "protocol": "trojan",
                "tag": "trojan",
                "settings": {
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
                        "quic-jls",
                        "trojan"
                    ]
                }
            },
            {
                "protocol": "quic-jls",
                "tag": "quic-jls",
                "settings": {
                    "certificate": "cert.pem",
                    "certificateKey": "key.pem",
                    "upstreamAddr":"codepen.io:443",
                    "alpn": [
                        "h3"
                    ],
                    "pwd": "user_pwd",
                    "iv": "user_iv",
                    "zeroRtt": false,
                    "congestionController": "bbr"
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

    std::env::set_var("TCP_DOWNLINK_TIMEOUT", "3");
    std::env::set_var("TCP_UPLINK_TIMEOUT", "3");

    let mut path = std::env::current_exe().unwrap();
    path.pop();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(&path.join("key.der"), &cert.serialize_private_key_der()).unwrap();
    std::fs::write(&path.join("cert.der"), &cert.serialize_der().unwrap()).unwrap();
    std::fs::write(&path.join("key.pem"), &cert.serialize_private_key_pem()).unwrap();
    std::fs::write(&path.join("cert.pem"), &cert.serialize_pem().unwrap()).unwrap();

    let configs = vec![config1.to_string(), config2.to_string()];
    common::test_configs(configs.clone(), "127.0.0.1", 1086);
    common::test_tcp_half_close_on_configs(configs.clone(), "127.0.0.1", 1086);
    common::test_data_transfering_reliability_on_configs(configs.clone(), "127.0.0.1", 1086);

    let configs = vec![config3.to_string(), config4.to_string()];
    common::test_configs(configs.clone(), "127.0.0.1", 1087);
}
