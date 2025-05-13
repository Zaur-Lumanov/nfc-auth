package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/ebfe/scard"
)

const (
	globalSalt = "nfc-auth-salt-2024" // Глобальная соль для генерации ключа
)

// NFCCard представляет структуру для работы с NFC картой
type NFCCard struct {
	ctx    *scard.Context
	card   *scard.Card
	reader string
}

// CryptoData представляет структуру для работы с шифрованием
type CryptoData struct {
	identifier []byte
	useUID     bool
	pinCode    string
}

// NewNFCCard создает новый экземпляр NFCCard
func NewNFCCard() (*NFCCard, error) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return nil, fmt.Errorf("ошибка инициализации контекста: %v", err)
	}

	readers, err := ctx.ListReaders()
	if err != nil {
		ctx.Release()
		return nil, fmt.Errorf("ошибка получения списка ридеров: %v", err)
	}

	if len(readers) == 0 {
		ctx.Release()
		return nil, fmt.Errorf("NFC ридеры не найдены")
	}

	return &NFCCard{
		ctx:    ctx,
		reader: readers[0],
	}, nil
}

// Connect подключается к NFC ридеру
func (n *NFCCard) Connect() error {
	card, err := n.ctx.Connect(n.reader, scard.ShareShared, scard.ProtocolAny)
	if err != nil {
		return fmt.Errorf("ошибка подключения к ридеру: %v", err)
	}

	n.card = card
	return nil
}

// Disconnect отключается от NFC ридера
func (n *NFCCard) Disconnect() {
	if n.card != nil {
		n.card.Disconnect(scard.ResetCard)
		n.card = nil
	}
}

// Release освобождает ресурсы
func (n *NFCCard) Release() {
	n.Disconnect()
	if n.ctx != nil {
		n.ctx.Release()
		n.ctx = nil
	}
}

// WaitForCard ожидает появления карты
func (n *NFCCard) WaitForCard() error {
	rs := []scard.ReaderState{
		{
			Reader:       n.reader,
			CurrentState: scard.StateUnaware,
		},
	}

	for {
		err := n.ctx.GetStatusChange(rs, -1)
		if err != nil {
			return fmt.Errorf("ошибка ожидания карты: %v", err)
		}

		if rs[0].EventState&scard.StatePresent != 0 {
			return nil
		}

		rs[0].CurrentState = rs[0].EventState
	}
}

// GetCardUID получает UID карты
func (n *NFCCard) GetCardUID() ([]byte, error) {
	if n.card == nil {
		return nil, fmt.Errorf("карта не подключена")
	}

	// Команда GET UID для ISO14443 карт
	cmd := []byte{0xFF, 0xCA, 0x00, 0x00, 0x00}
	resp, err := n.card.Transmit(cmd)
	if err != nil {
		return nil, fmt.Errorf("ошибка получения UID: %v", err)
	}

	if len(resp) < 2 {
		return nil, fmt.Errorf("неверный ответ от карты")
	}

	// Проверяем статус ответа
	if resp[len(resp)-2] != 0x90 || resp[len(resp)-1] != 0x00 {
		return nil, fmt.Errorf("ошибка в ответе карты: %02X %02X", resp[len(resp)-2], resp[len(resp)-1])
	}

	// Возвращаем UID (все байты кроме последних двух, которые являются статусом)
	return resp[:len(resp)-2], nil
}

// GetCardATR получает ATR карты
func (n *NFCCard) GetCardATR() ([]byte, error) {
	if n.card == nil {
		return nil, fmt.Errorf("карта не подключена")
	}

	status, err := n.card.Status()
	if err != nil {
		return nil, fmt.Errorf("ошибка получения статуса карты: %v", err)
	}

	return status.Atr, nil
}

// NewCryptoData создает новый экземпляр CryptoData
func NewCryptoData(identifier []byte, useUID bool, pinCode string) *CryptoData {
	return &CryptoData{
		identifier: identifier,
		useUID:     useUID,
		pinCode:    pinCode,
	}
}

// generateKey генерирует ключ на основе идентификатора карты, PIN-кода и глобальной соли
func (c *CryptoData) generateKey() []byte {
	data := append(c.identifier, []byte(c.pinCode)...)
	data = append(data, []byte(globalSalt)...)
	hash := sha256.Sum256(data)
	return hash[:]
}

// encrypt шифрует данные с использованием AES
func (c *CryptoData) encrypt(plaintext string) (string, error) {
	key := c.generateKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("ошибка создания шифра: %v", err)
	}

	// Создаем IV
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", fmt.Errorf("ошибка генерации IV: %v", err)
	}

	// Создаем режим шифрования
	mode := cipher.NewCBCEncrypter(block, iv)

	// Дополняем данные до размера блока
	padding := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	paddedData := make([]byte, len(plaintext)+padding)
	copy(paddedData, plaintext)
	for i := len(plaintext); i < len(paddedData); i++ {
		paddedData[i] = byte(padding)
	}

	// Шифруем данные
	ciphertext := make([]byte, len(paddedData))
	mode.CryptBlocks(ciphertext, paddedData)

	// Объединяем IV и зашифрованные данные
	result := append(iv, ciphertext...)
	return base64.StdEncoding.EncodeToString(result), nil
}

// decrypt расшифровывает данные с использованием AES
func (c *CryptoData) decrypt(encodedData string) (string, error) {
	// Декодируем base64
	data, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return "", fmt.Errorf("ошибка декодирования base64: %v", err)
	}

	if len(data) < aes.BlockSize {
		return "", fmt.Errorf("неверный размер данных")
	}

	key := c.generateKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("ошибка создания шифра: %v", err)
	}

	// Извлекаем IV
	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	// Создаем режим расшифровки
	mode := cipher.NewCBCDecrypter(block, iv)

	// Расшифровываем данные
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Удаляем дополнение
	padding := int(plaintext[len(plaintext)-1])
	if padding > aes.BlockSize || padding == 0 {
		return "", fmt.Errorf("неверное дополнение")
	}

	return string(plaintext[:len(plaintext)-padding]), nil
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Использование: go run main.go [encode|decode|dbg|dbg2] [--uid] \"данные\"")
	}

	mode := os.Args[1]
	useUID := false
	data := ""

	// Обработка аргументов
	args := os.Args[2:]
	for i, arg := range args {
		if arg == "--uid" {
			useUID = true
			// Удаляем флаг из аргументов
			args = append(args[:i], args[i+1:]...)
			break
		}
	}

	if len(args) == 0 {
		log.Fatal("Использование: go run main.go [encode|decode|dbg|dbg2] [--uid] \"данные\"")
	}
	data = args[0]

	// Режимы отладки остаются без изменений
	if mode == "dbg" || mode == "dbg2" {
		nfc, err := NewNFCCard()
		if err != nil {
			log.Fatalf("Ошибка инициализации NFC: %v", err)
		}
		defer nfc.Release()

		fmt.Printf("Подключение к ридеру: %s\n", nfc.reader)
		fmt.Println("Режим отладки (UID): ожидание карт...")
		fmt.Println("Нажмите Ctrl+C для выхода")

		// Бесконечный цикл для мониторинга карт
		for {
			// Ожидаем появления карты
			err = nfc.WaitForCard()
			if err != nil {
				log.Printf("Ошибка ожидания карты: %v", err)
				time.Sleep(time.Second)
				continue
			}

			// Подключаемся к карте
			err = nfc.Connect()
			if err != nil {
				log.Printf("Ошибка подключения к карте: %v", err)
				time.Sleep(time.Second)
				continue
			}

			var identifier []byte
			if mode == "dbg" {
				// Получаем UID
				identifier, err = nfc.GetCardUID()
				if err != nil {
					log.Printf("Ошибка чтения UID: %v", err)
					nfc.Disconnect()
					time.Sleep(time.Second)
					continue
				}
				fmt.Printf("Карта обнаружена! UID: %X\n", identifier)
			} else {
				// Получаем ATR
				identifier, err = nfc.GetCardATR()
				if err != nil {
					log.Printf("Ошибка чтения ATR: %v", err)
					nfc.Disconnect()
					time.Sleep(time.Second)
					continue
				}
				fmt.Printf("Карта обнаружена! ATR: %X\n", identifier)
			}

			// Отключаемся от карты и ждем, пока она будет убрана
			nfc.Disconnect()
			time.Sleep(time.Second)
		}
	}

	nfc, err := NewNFCCard()
	if err != nil {
		log.Fatalf("Ошибка инициализации NFC: %v", err)
	}
	defer nfc.Release()

	fmt.Printf("Подключение к ридеру: %s\n", nfc.reader)
	fmt.Println("Ожидание карты...")

	// Ожидаем появления карты
	err = nfc.WaitForCard()
	if err != nil {
		log.Fatalf("Ошибка ожидания карты: %v", err)
	}

	// Подключаемся к карте
	err = nfc.Connect()
	if err != nil {
		log.Fatalf("Ошибка подключения к карте: %v", err)
	}
	defer nfc.Disconnect()

	var identifier []byte
	if useUID {
		// Получаем UID
		identifier, err = nfc.GetCardUID()
		if err != nil {
			log.Fatalf("Ошибка чтения UID: %v", err)
		}
		fmt.Printf("Карта обнаружена! UID: %X\n", identifier)
	} else {
		// Получаем ATR
		identifier, err = nfc.GetCardATR()
		if err != nil {
			log.Fatalf("Ошибка чтения ATR: %v", err)
		}
		fmt.Printf("Карта обнаружена! ATR: %X\n", identifier)
	}

	// Запрашиваем PIN-код
	fmt.Print("Введите PIN-код (или нажмите Enter для пустого PIN-кода): ")
	var pinCode string
	fmt.Scanln(&pinCode)

	// Если введен только Enter, устанавливаем пустой PIN-код
	if pinCode == "" {
		fmt.Println("Используется пустой PIN-код")
	}

	crypto := NewCryptoData(identifier, useUID, pinCode)

	switch mode {
	case "encode":
		encoded, err := crypto.encrypt(data)
		if err != nil {
			log.Fatalf("Ошибка шифрования: %v", err)
		}
		// Добавляем префикс для указания типа идентификатора
		prefix := "ATR:"
		if useUID {
			prefix = "UID:"
		}
		fmt.Printf("Зашифрованные данные: %s%s\n", prefix, encoded)

	case "decode":
		// Проверяем префикс для определения типа идентификатора
		if len(data) < 4 {
			log.Fatal("Неверный формат зашифрованных данных")
		}
		prefix := data[:4]
		encryptedData := data[4:]

		if prefix != "UID:" && prefix != "ATR:" {
			log.Fatal("Неверный формат зашифрованных данных")
		}

		// Проверяем соответствие типа идентификатора
		expectedType := "ATR"
		if useUID {
			expectedType = "UID"
		}
		if (prefix == "UID:") != useUID {
			log.Fatalf("Несоответствие типа идентификатора. Ожидается %s, но данные зашифрованы с %s",
				expectedType,
				prefix[:3])
		}

		decoded, err := crypto.decrypt(encryptedData)
		if err != nil {
			log.Fatalf("Ошибка расшифровки: %v", err)
		}
		fmt.Printf("Расшифрованные данные: %s\n", decoded)

	default:
		log.Fatal("Неизвестный режим. Используйте 'encode', 'decode', 'dbg' или 'dbg2'")
	}
}
