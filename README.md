1.Instalasi Dependency
2. Setting File di Codeigniter:
2.1 Buat File Hooks.php dalam folder App\Config
2.2 Buat Hooks\RequestLogger.php
2.3 Buat Libaries\UserRequestLogger.php
3.4 Aktifkan Hook di App\Config\Event.php (Events::on('post_controller_constructor', 'App\Hooks\RequestLogger::logRequest');)
3.5  File hasil akan di simpan kekdalam folder Writeable. dan bisa disesuaikan.