import io
import os
import _pickle

import pyAesCrypt


maxKeySize = 1024
bufferSize = 64 * 1024


def itEncrypt(path):
    ''' Проверяет файл на шифрование.
        True, если файл шифрован. False, если файл не шифрован. '''
    with open(path, 'rb') as fIn:
        if fIn.read()[: 3] == b'AES':
            return True
    return False


def encryptFile(path, key):
    ''' Шифрует содержание файла. '''
    with open(path, 'rb') as fIn:
        IOIn = io.BytesIO(fIn.read())

    with open(path, 'wb') as fOut:
        try:
            pyAesCrypt.encryptStream(IOIn, fOut, key, bufferSize)
        except:
            fOut.seek(0)
            fOut.write(IOIn.getvalue())
            raise


def decryptFile(path, key):
    ''' Дешифрует содержание файла.  '''
    with open(path, 'rb') as fIn:
        IOIn = io.BytesIO(fIn.read())
        IOInSize = len(IOIn.getvalue())

    with open(path, 'wb') as fOut:
        try:
            pyAesCrypt.decryptStream(IOIn, fOut, key, bufferSize, IOInSize)
        except:
            fOut.seek(0)
            fOut.write(IOIn.getvalue())
            raise


def setByte(path, key, bdata):
    ''' Записывает в файл шифрованный bdata <class 'bytes'>. '''
    with open(path, 'rb') as fIn:
        backup = fIn.read()

    with open(path, 'wb') as fOut:
        IOIn = io.BytesIO(bdata)
        try:
            pyAesCrypt.encryptStream(IOIn, fOut, key, bufferSize)
        except:
            fOut.seek(0)
            fOut.write(backup)
            raise


def getByte(path, key):
    ''' Возвращяет дешифрованное содержание файла в <class 'bytes'>. '''
    with open(path, 'rb') as fIn:
        IOOut = io.BytesIO()
        fInSize = os.path.getsize(path)

        pyAesCrypt.decryptStream(fIn, IOOut, key, bufferSize, fInSize)
    return IOOut.getvalue()


def setObj(path, key, obj):
    ''' Записывает в файл шифрованный сериализованный obj. '''
    with open(path, 'rb') as fIn:
        backup = fIn.read()

    with open(path, 'wb') as fOut:
        IOIn = io.BytesIO()
        _pickle.dump(obj, IOIn)
        IOIn.seek(0)
        try:
            pyAesCrypt.encryptStream(IOIn, fOut, key, bufferSize)
        except:
            fOut.seek(0)
            fOut.write(backup)
            raise


def getObj(path, key):
    ''' Возвращяет десериализированый дешифрованный объект файла. '''
    with open(path, 'rb') as fIn:
        IOOut = io.BytesIO()
        fInSize = os.path.getsize(path)

        pyAesCrypt.decryptStream(fIn, IOOut, key, bufferSize, fInSize)
        IOOut.seek(0)
    return _pickle.load(IOOut)


# relur 70
