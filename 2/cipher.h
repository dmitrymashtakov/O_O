/** @file сipher.h
 * @author Маштаков Д.С.
 * @version 1.0
 * @date 22.11.2024
 * @copyright ИБСТ ПГУ
 */
#pragma once
#include <string>
#include <locale>
#include <iostream>
#include <map>
#include <stdexcept>
#include <cmath>
using namespace std;
/** @brief Шифрование методом табличной маршрутной перестановки
 * @details Ключ устанавливается в конструкторе.
 * Для зашифровывания и расшифровывания предназначены методы encrypt и decrypt.
 * @warning Реализация только для английского языка
 */
class cipher {
private:
    int stolb; ///< количество столбцов
    /**
     * @brief Проверка валидации ключа
     * 
     * Проверяет, что ключ не более половины длины шифруемого сообщения.
     * 
     * @param s Входная строка, представляющая ключ, строка с текстом.
     * @return ключ, который равен половины длины строки.
     */
    int isValidKey(int key,string s); 
    /**
     * @brief Проверка знака ключа
     * 
     * Проверяет, что ключ более нуля
     * 
     * @param s Входная строка, представляющая ключ.
     * @throw cipher_error, если ключ <= 0
     */
    bool isPlusKey(int key);
    /**
     * @brief Проверка символов строки
     * 
     * Проверяет, есть ли в сообщении символы, отличные от букв английского алфавита
     * 
     * @param s Входная строка, представляющая текст.
     * @throw cipher_error, если присутствуют некорректные символы
     */
    bool isValidText(const string& text);
    /**
     * @brief Валидация зашифрованного текста
     * 
     * Приводит символы строки к верхнему регистру
     * 
     * @param ws Входная строка, представляющая текст.
     * @throw cipher_error если строка пуста
     */
    string getValidOpenText(const std::string& s);
    
public:
    cipher(int key); ///< конструктор
    cipher() = delete; ///< запрект конструктора без параметров
    /**
 	* @brief Зашифровывание
 	* @param [in] text Открытый текст. Не должен быть пустой строкой.
 	* Строчные символы автоматически преобразуются к прописным.
 	* Все не-буквы удаляются
 	* @return Зашифрованная строка
 	* @throw cipher_error, если текст пустой
 	*/
    string encrypt(string text);
    /**
 	* @brief Расшифровывание
 	* @param [in] ctext Шифрованный текст должен быть пустой строкой.
 	* Строчные символы автоматически преобразуются к прописным.
 	* Все не-буквы удаляются
 	* @return Зашифрованная строка
 	* @throw cipher_error, если текст пустой
 	*/
    string decrypt(string text);
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
