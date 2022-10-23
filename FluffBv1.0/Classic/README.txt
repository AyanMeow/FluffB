本程序测试环境包括Ubuntu22.04、kali20.x，注意在虚拟机和WSL环境下可能出现蓝牙无法打开或搜索不到设备的问题。
程序运行需要蓝牙开发环境支持，可以通过以下命令安装。
1.Sudo apt-get install bluez
2.#安装bluez
3.Sudo apt-get install libbluetooth-dev
4.#安装蓝牙开发库
5.Sudo apt-get install build-essential
6.#安装C/C++开发环境
环境安装后可以进行，编译时需要使用“-lbluetooth”参数链接依赖库。具体命令如下。
1.gcc –o [name-of-executable-program] fuzzer-g.c -lbluetooth
在开始测试前，首先要开启蓝牙服务，使用以下命令。
1.	sudo service Bluetooth start 
靶机同样需要开启蓝牙，可以在主机的蓝牙设置中尝试连接靶机测试可用性。为了避免出现配对被拒绝的情形，可以尝试正常连接靶机再断开。
随后可以在root账户下或使用sudo命令运行fuzzer程序，程序会自动搜索可用的蓝牙设备并列出其名称与地址。
如果没有搜索到蓝牙请确认靶机的可用性，确保靶机没有与任何蓝牙设备连接并处于搜索设备状态，然后重复搜索。如果出现“host is dowm”错误，请确保靶机处于开启状态。如果出现“permission denied”错误，请检查程序运行时是否具有root权限。
在可用的蓝牙设备中选择目标设备，程序会提示是否需要扫描目标设备提供的服务，此功能由SDP协议提供。输入Y/y确认扫描如图5-4，输入N/n跳过。
输入对应的序号选择要挖掘的协议，此时会提示是否需要接收返回包的选项，如图5-6，若选择是(Y/y)，则日志中会记录所有返回包，日志位置在logs文件夹中，如图5-7。选择完成后挖掘就会开始。