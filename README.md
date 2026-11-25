从外部导入的归档包解压后，文件属主变成了包里的数字，一个普通文件被设上了提权位：解压器必须把属主与属组重映射为解压进程身份，权限位必须剥离所有特权位，设备文件、块设备与命名管道必须拒绝，硬链接只允许指向包内已存在条目，目录权限不得可写，批量解压时各包相互独立。不变量是解压出的文件属主必定是当前进程，且任何特权位都不会出现在结果中。

策略

策略字典包含 remap_owner、strip_privileged、allow_devices 三个布尔字段。合规策略要求 remap_owner 与 strip_privileged 为真，allow_devices 为假。

测试

在仓库根目录运行 python -m pytest tests -q。