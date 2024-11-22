/** @file modAlphaCipher.h
 * @author Маштаков Д.С.
 * @version 1.0
 * @date 22.11.2024
 * @copyright ИБСТ ПГУ
 */

#pragma once
#include <map>
#include <string>
#include <vector>
#include <stdexcept>
#include <locale>
#include <codecvt>
#include <iostream>

/** @brief Шифрование методом Гронсфельда
 * @details Ключ устанавливается в конструкторе.
 * Для зашифровывания и расшифровывания предназначены методы encrypt и decrypt.
 * @warning Реализация только для русского языка
 */
class modAlphaCipher
{
private:
    std::wstring numAlpha = L"АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"; ///< Алфавит
    std::map<char, int> alphaNum; ///< Ассоциативный массив "номер по символу"
    std::vector<int> key; ///< Ключ 
    std::vector<int> convert(const std::wstring& s); ///< Преобразование строки в вектор
    std::wstring convert(const std::vector<int>& v); ///< Преобразование вектора в строку
    /**
     * @brief Валидация ключа
     * 
     * Проверяет, что ключ не пустой и не содержит символов, не принадлежащих алфавиту.
     * 
     * @param s Входная строка, представляющая ключ.
     * @throw cipher_error Если ключ пустой или содержит недопустимые символы.
     */
    std::wstring getValidKey(const std::wstring & s);
     /**
     * @brief Валидация открытого текста
     * 
     * Проверяет, что открытый текст содержит только допустимые символы алфавита.
     * 
     * @param ws Входная строка, представляющая открытый текст.
     * @throw cipher_error Если открытый текст содержит недопустимые символы.
     */
    std::wstring getValidOpenText(const std::wstring& s);
    /**
     * @brief Валидация зашифрованного текста
     * 
     * Проверяет, что зашифрованный текст содержит только допустимые символы алфавита.
     * 
     * @param ws Входная строка, представляющая зашифрованный текст.
     * @throw cipher_error Если зашифрованный текст содержит недопустимые символы.
     */
    std::wstring getValidCipherText(const std::wstring& s);

public:
    modAlphaCipher() = delete; ///< Запрет на использование конструктора по умолчанию
    /**
     * @brief Конструктор для установки ключа
     * 
     * @param skey Строка, представляющая ключ для шифрования.
     */
    modAlphaCipher(const std::wstring& skey);
     /**
 	* @brief Зашифровывание
 	* @param [in] open_text Открытый текст. Не должен быть пустой строкой.
 	* Строчные символы автоматически преобразуются к прописным.
 	* Все не-буквы удаляются
 	* @return Зашифрованная строка
 	* @throw cipher_error, если текст пустой
 	*/
    std::wstring encrypt(const std::wstring& open_text);
    /**
 	* @brief Расшифровывание
 	* @param [in] cipher_text Шифрованный текст должен быть пустой строкой.
 	* Строчные символы автоматически преобразуются к прописным.
 	* Все не-буквы удаляются
 	* @return Зашифрованная строка
 	* @throw cipher_error, если текст пустой
 	*/
    std::wstring decrypt(const std::wstring& cipher_text);
};
/**
 * @brief Обработка исключений
 * 
 * Класс, созданный для обработки ошибок
 * 
 */
class cipher_error : public std::invalid_argument
{
public:
 /**
     * @brief Конструктор с аргументом типа std::string
     * 
     * @param what_arg Сообщение об ошибке.
     */
    explicit cipher_error(const std::string& what_arg): 
    std::invalid_argument(what_arg){}
    /**
     * @brief Конструктор с аргументом типа const char*
     * 
     * @param what_arg Сообщение об ошибке.
     */
    explicit cipher_error(const char* what_arg): 
    std::invalid_argument(what_arg){}
};
