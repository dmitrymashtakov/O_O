#include "cipher.h"
#include "cipher.cpp"
#include <UnitTest++/UnitTest++.h>
#include <locale>
#include <iostream>
#include <string>

SUITE(KeyTest) {
	TEST(ValidKey) 
    	{ cipher c(3);
    	CHECK_EQUAL(c.encrypt("PRIVET"), "ITREPV"); }
    TEST(EmptyKey) 
    	{ CHECK_THROW(cipher c(), cipher_error); }
	TEST(InvalidKey) 
    	{ CHECK_THROW(cipher c(-1), cipher_error); }
    TEST(FloatKey) 
    	{ CHECK_THROW(cipher c(-14.02), cipher_error); }
    TEST(BigKey) 
    { 
        cipher c(100);
        CHECK_EQUAL("TEVIRP", c.encrypt("PRIVET"));
    }
}
SUITE(EncryptTest)
{
	
    TEST(UpString) 
    { 
        cipher c(3);
        CHECK_EQUAL("ITREPV", c.encrypt("PRIVET"));
    }
    TEST(LowString) 
    { 
        cipher c(3);
        CHECK_EQUAL("ITREPV", c.encrypt("pRiVet"));
    }

    TEST(EmptyString) 
    { 
        cipher c(3);
        CHECK_THROW(c.encrypt(""), cipher_error);
    }

    TEST(DigestText) 
    { 
        cipher c(3);
        CHECK_EQUAL("ITREPV", c.encrypt("PRIVET123"));
    }
    TEST(PunctuationUndSpaceText) 
    { 
        cipher c(3);
        CHECK_EQUAL("ITREPV", c.encrypt("PR I V, ET"));
    }
}

SUITE(DecryptTest)
{
    TEST(UpString) 
    { 
        cipher c(3);
        CHECK_EQUAL("PRIVET", c.decrypt("ITREPV")); 
    }
    TEST(LowString) 
    { 
        cipher c(3);
        CHECK_EQUAL("PRIVET", c.decrypt("ItRePv")); 
    }

    TEST(EmptyString) 
    { 
        cipher c(3);
        CHECK_THROW(c.decrypt(""), cipher_error);
    }
    TEST(DigestText) 
    { 
        cipher c(3);
        CHECK_EQUAL("PRIVET", c.decrypt("ITREPV123"));
    }
    TEST(PunctuationUndSpaceText) 
    { 
        cipher c(3);
        CHECK_EQUAL("PRIVET", c.decrypt("IT! RE P V"));
    }
}

int main() {
    return UnitTest::RunAllTests();
}
