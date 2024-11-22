#include "modAlphaCipher.cpp"
#include "modAlphaCipher.h"

#include <UnitTest++/UnitTest++.h>
#include <locale>
using namespace std;
SUITE(KeyTest)
{
    TEST(ValidKey) { 
    wstring z1 = L"АЯЯКАМДС";
    wstring z2 = modAlphaCipher(L"АСЯ").encrypt(L"АНАКОНДА");
    if (z1==z2) {
    CHECK(true);
    }
    else {
    CHECK(false);
    }
    }
    TEST(LongKey) { 
    wstring z3 = L"ПСМ";
    wstring z4 = modAlphaCipher(L"ПАНДЕМОНИУМ").encrypt(L"АСЯ");
    if (z3==z4) {
    CHECK(true);
    }
    else {
    CHECK(false);
    }
    }
    TEST(LowCaseKey) { 
    wstring z5 = L"АЯЯКАМДС";
    wstring z6 = modAlphaCipher(L"ася").encrypt(L"АНАКОНДА");
    if (z5==z6) {
    CHECK(true);
    }
    else {
    CHECK(false);
    }
    }
    TEST(DigitsInKey) { CHECK_THROW(modAlphaCipher cp(L"Б1"), cipher_error); }
    TEST(PunctuationInKey) { CHECK_THROW(modAlphaCipher cp(L"Б,С"), cipher_error); }
    TEST(WhitespaceInKey) { CHECK_THROW(modAlphaCipher cp(L"Б С"), cipher_error); }
    TEST(EmptyKey) { CHECK_THROW(modAlphaCipher cp(L""), cipher_error); }
    TEST(WeakKey) { CHECK_THROW(modAlphaCipher cp(L"ААА"), cipher_error); }
}
struct KeyB_fixture {
    modAlphaCipher* p;
    KeyB_fixture() { p = new modAlphaCipher(L"Б"); }
    ~KeyB_fixture() { delete p; }
};
SUITE(EncryptTest)
{
 TEST_FIXTURE(KeyB_fixture, UpCaseString){
 wstring z7 = L"ТУБМЭДСПИЙУЦПМПЕОПКТНЁСУЭЯОБНОЁРСЙГЬЛБУЭСБКНБОЙУРСЁЛСБТОПКУСЁМЭЯФЗОЁЕПМДПЗЕБУЭ";
 wstring z8 = p->encrypt(L"СТАЛЬГРОЗИТХОЛОДНОЙСМЕРТЬЮНАМНЕПРИВЫКАТЬРАЙМАНИТПРЕКРАСНОЙТРЕЛЬЮУЖНЕДОЛГОЖДАТЬ");
 if (z7==z8) {
 CHECK(true);
 }
 else {
 CHECK(false);
 } 
 }
 TEST_FIXTURE(KeyB_fixture, LowCaseString){
 wstring z9 = L"ТУБМЭДСПИЙУЦПМПЕОПКТНЁСУЭЯОБНОЁРСЙГЬЛБУЭСБКНБОЙУРСЁЛСБТОПКУСЁМЭЯФЗОЁЕПМДПЗЕБУЭ";
 wstring z10 = p->encrypt(L"стальгрозитхолоднойсмертьюнамнепривыкатьрайманитпрекраснойтрельюужнедолгождать");
 if (z9==z10) {
 CHECK(true);
 }
 else {
 CHECK(false);
 } 
 }
 TEST_FIXTURE(KeyB_fixture, StringWithWhitspaceAndPunct){
 wstring z11 = L"ТУБМЭДСПИЙУЦПМПЕОПКТНЁСУЭЯОБНОЁРСЙГЬЛБУЭСБКНБОЙУРСЁЛСБТОПКУСЁМЭЯФЗОЁЕПМДПЗЕБУЭ";
 wstring z12 = p->encrypt(L"СТАЛЬ ГРОЗИТ ХОЛОДНОЙ СМЕРТЬЮ, НАМ НЕ ПРИВЫКАТЬ, РАЙ МАНИТ ПРЕКРАСНОЙ ТРЕЛЬЮ , УЖ НЕ ДОЛГО ЖДАТЬ");
 if (z11==z12) {
 CHECK(true);
 }
 else {
 CHECK(false);
 }
 }
 TEST_FIXTURE(KeyB_fixture, StringWithNumbers){
 wstring z13 = L"ТОПГЬНДПЕПН";
 wstring z14 = p->encrypt(L"Сновым2024годом");
 if (z13==z14) {
 CHECK(true);
 }
 else {
 CHECK(false);
 }
 }
 TEST_FIXTURE(KeyB_fixture, EmptyString) {
 CHECK_THROW(p->encrypt(L""),cipher_error);
 }
 TEST_FIXTURE(KeyB_fixture, NoAlphaString) {
 CHECK_THROW(p->encrypt(L"1234+8765=9999"),cipher_error);
 }
 TEST(MaxShiftKey){
 wstring z15 = L"РСЯКЫВПНЖЗСФНКНГМНИРЛДПСЫЭМЯЛМДОПЗБЪЙЯСЫПЯИЛЯМЗСОПДЙПЯРМНИСПДКЫЭТЁМДГНКВНЁГЯСЫ";
 wstring z16 = modAlphaCipher(L"Я").encrypt(L"СТАЛЬГРОЗИТХОЛОДНОЙСМЕРТЬЮНАМНЕПРИВЫКАТЬРАЙМАНИТПРЕКРАСНОЙТРЕЛЬЮУЖНЕДОЛГОЖДАТЬ");
 if (z15==z16) {
 CHECK(true);
 }
 else {
 CHECK(false);
 } 
 }
}
 
SUITE(DecryptText)
{
 TEST_FIXTURE(KeyB_fixture, UpCaseString) {
 wstring z17 = L"СТАЛЬГРОЗИТХОЛОДНОЙСМЕРТЬЮНАМНЕПРИВЫКАТЬРАЙМАНИТПРЕКРАСНОЙТРЕЛЬЮУЖНЕДОЛГОЖДАТЬ";
 wstring z18 = p->decrypt(L"ТУБМЭДСПИЙУЦПМПЕОПКТНЁСУЭЯОБНОЁРСЙГЬЛБУЭСБКНБОЙУРСЁЛСБТОПКУСЁМЭЯФЗОЁЕПМДПЗЕБУЭ");
 if (z17==z18) {
 CHECK(true);
 }
 else {
 CHECK(false);
 }
 } 
 TEST_FIXTURE(KeyB_fixture, LowCaseString) {
 CHECK_THROW(p->decrypt(L"фывЫФВЫФЧФЫЫФВЫФСЧЯСЧЯМЧЯМ"),cipher_error);
 }
 TEST_FIXTURE(KeyB_fixture, WhitespaceString) {
 CHECK_THROW(p->decrypt(L"ФЫВ ЫФВ ЫФЧФ ЫФВ ЫФСЧ ЯСЧЯМЧ ЯМ"),cipher_error);
 }
 TEST_FIXTURE(KeyB_fixture, DigitsString) {
 CHECK_THROW(p->decrypt(L"ФЫВЫФВЫФЧ123445ФЫЫФВЫФСЧЯСЧЯМЧЯМ"),cipher_error);
 }
 TEST_FIXTURE(KeyB_fixture, PunctString) {
 CHECK_THROW(p->decrypt(L"ФЫВЫФВЫФЧ,ЫЫФВЫФСЧЯСЧЯМЧЯМ"),cipher_error);
 }
 TEST_FIXTURE(KeyB_fixture, EmptyString) {
 CHECK_THROW(p->decrypt(L""),cipher_error);
 }
 TEST(MaxShiftKey) {
 wstring z19 = L"СТАЛЬГРОЗИТХОЛОДНОЙСМЕРТЬЮНАМНЕПРИВЫКАТЬРАЙМАНИТПРЕКРАСНОЙТРЕЛЬЮУЖНЕДОЛГОЖДАТЬ";
 wstring z20 = modAlphaCipher(L"Я").decrypt(L"РСЯКЫВПНЖЗСФНКНГМНИРЛДПСЫЭМЯЛМДОПЗБЪЙЯСЫПЯИЛЯМЗСОПДЙПЯРМНИСПДКЫЭТЁМДГНКВНЁГЯСЫ");
 if (z19==z20) {
 CHECK(true);
 }
 else {
 CHECK(false);
 }
 }

}
int main(int argc, char** argv) {
	std::locale loc("ru_RU.UTF-8");
    std::locale::global(loc);
	return UnitTest::RunAllTests(); }

