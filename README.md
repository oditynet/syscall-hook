https://syscalls64.paolostivanin.com/
Решил я значит поставить хук на безобидный вызов read и изменить читаемые данные на 0, но только потом до меня дошло,что процесс записи - это и процесс чтения 

```
openat(AT_FDCWD, "/tmp/8c9a0b849e5847cec5e1af878b9ae512-{87A94AB0-E370-4cde-98D3-ACC110C5967D}", O_RDONLY) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=89, ...}) = 0
fadvise64(3, 0, 0, POSIX_FADV_SEQUENTIAL) = 0
mmap(NULL, 270336, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7993aa71e000
read(3, "3168\ntelegram\nviva\n2cafb2a1191e4"..., 262144) = 89
write(1, "3168\ntelegram\nviva\n2cafb2a1191e4"..., 893168
```
