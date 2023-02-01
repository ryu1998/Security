import socket

target_host = "127.0.0.1"
target_port = 8080

#ソケットオブジェクトの作成
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.bind(('127.0.0.3', 8080))

#サーバーへ接続
client.connect((target_host, target_port))

#データの送信
client.send(b"Data by TCP Client!!")

#データの受信
response = client.recv(4096)

print("success!")
print(response.decode())
client.close()