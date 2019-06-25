# cryptflib

python библиотека, что ли, Для шифрования файлов. Работает на базе библиотеки PyAesCrypt(https://github.com/marcobellaccini/pyAesCrypt)

Замечание: шифрует файлы больших размеров относительно долго. Так же, для сохраняет данных в RAM, для сохранности в случае ошибки.
Учитывайте размеры файла, который собираетесь шифрануть.

Описание:
+ itEncrypt(path) - Проверяет является ли файл шифрованным этой библиотекой. Возвращает True, шифрован, иначе False.

+ encryptFile(path, key) - Шифрует содержание файла по ключу key.
+ decryptFile(path, key) - Дешифрует содержание файла по ключу key.

+ setByte(path, key, bdata) - Записывает зашифрованный bdata(типа bytes) в файл.
+ getByte(path, key) - Возвращает дешифрованное содержание файла в байт коде .

+ setObj(path, key, obj) - Записывает зашифрованный сериализованный объект в файл.
+ getObj(path, key) - Возвращает дешифрованный объект содержащийся в файле.