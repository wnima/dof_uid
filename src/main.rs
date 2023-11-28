use std::{
    fs::{self, File},
    io::{Read, Write},
    path::Path,
};

use base64::encode;
use clap::{App, Arg};
use hex;
use openssl::rsa::{Padding, Rsa};

fn main() {
    let uid_help = r#"指定用户UID"#;
    let key_help = r#"指定RSA私钥路径"#;

    let matches = App::new("dof_uid")
        .version("0.0.1")
        .author("wonima")
        .about("dof uid token gen tools")
        .arg(
            Arg::with_name("UID")
                .long("uid")
                .short("u")
                .takes_value(true)
                .help(uid_help),
        )
        .arg(
            Arg::with_name("PRIVATE_KEY")
                .long("key")
                .short("k")
                .takes_value(true)
                .help(key_help),
        )
        .get_matches();
    let uid;
    if let Some(params) = matches.value_of("UID") {
        uid = params;
    } else {
        println!("没有用户UID");
        return;
    }
    let private_key_path;
    if let Some(params) = matches.value_of("PRIVATE_KEY") {
        private_key_path = params;
    } else {
        println!("未指定私钥路径");
        return;
    }
    exec(uid.parse().unwrap(), private_key_path)
}

fn exec(uid: i32, private_key_path: &str) {
    // 加载私钥
    let private_key_pem = load_file(private_key_path);
    
    // UID转十六进制 长度不足八，前面补0
    let hex_uid = format!("{:08x}", uid);
    println!("转十六进制 长度不足八位前面补0====>\t{}", hex_uid);

    // 盐? 补码？
    let raw_uid = format!(
        "{}010101010101010101010101010101010101010101010101010101010101010155914510010403030101",
        hex_uid
    );
    let uid_data = hex::decode(&raw_uid).unwrap();
    println!("拼装====>\t{}", raw_uid);

    // 加载rsa私钥
    let rsa = Rsa::private_key_from_pem(private_key_pem.as_bytes()).unwrap();
    let pem = rsa.private_key_to_pem().unwrap();
    println!("私钥====>\t{:?}", String::from_utf8_lossy(&pem));

    // rsa 私钥加密
    let mut buf = vec![0; rsa.size() as usize];
    rsa.private_encrypt(&uid_data, &mut buf, Padding::PKCS1)
        .unwrap();
    let token = encode(buf);
    println!("完成====>\t{}", token);
    
    // 保存
    save_file(format!("{}.token", uid).as_str(), &token);
}

fn save_file(path: &str, content: &str) {
    let mut f = fs::File::create(&path).unwrap();
    let _ = f.write_all(content.as_bytes());
}

fn load_file(path: &str) -> String {
    let path_name = Path::new(&path);
    let display = path_name.display();
    let mut file = match File::open(&path_name) {
        Ok(file) => file,
        Err(_why) => {
            panic!("文件不存在 {}", display);
        }
    };

    let mut s = String::new();
    match file.read_to_string(&mut s) {
        Err(why) => panic!("无法打开文件 {}: {}", display, why.to_string()),
        Ok(_) => println!("读取文件成功 {}", display),
    }
    s // 返回文件内容
}
