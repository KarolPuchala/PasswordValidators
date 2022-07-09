from password_validator import (
    HasLowerCharacterValidator, 
    HasUpperCharacterValidator, 
    HasNumberValidator, 
    HasSpecialCharacterValidator, 
    LengthValidator,
    HaveIbeenPwnedValidator,
    ValidationError,
    PasswordValidator
)

import requests_mock
import pytest


def test_if_has_lower_character_validator_positive():
    # given
    validator = HasLowerCharacterValidator('TEsT')

    # when
    result = validator.is_valid()

    # then
    assert result is True


def test_if_has_lower_character_validator_all_upper_char():
    # given
    validator = HasLowerCharacterValidator('TEST')

    # when
    with pytest.raises(ValidationError) as error:
        result = validator.is_valid()
        
        # then
        assert 'Text must contain at least one lowercase letter' in str(error.value)


def test_if_has_lower_character_validator_all_digit():
    # given
    validator = HasLowerCharacterValidator('1234')

    # when
    with pytest.raises(ValidationError) as error:
        result = validator.is_valid()
        
        # then
        assert 'Text must contain at least one lowercase letter' in str(error.value)


def test_if_has_lower_character_validator_all_punctuation():
    # given
    validator = HasLowerCharacterValidator('!@#$%')

    # when
    with pytest.raises(ValidationError) as error:
        result = validator.is_valid()
        
        # then
        assert 'Text must contain at least one lowercase letter' in str(error.value)


def test_if_has_upper_character_validator_positive():
    # given
    validator = HasUpperCharacterValidator('teSt')

    # when
    result = validator.is_valid()

    # then
    assert result is True


def test_if_has_upper_character_validator_all_lower_char():
    # given
    validator = HasUpperCharacterValidator('test')

    # when
    with pytest.raises(ValidationError) as error:
        result = validator.is_valid()
        
        # then
        assert 'Text must contain at least one uppercase letter' in str(error.value)


def test_if_has_upper_character_validator_all_digit():
    # given
    validator = HasUpperCharacterValidator('1234')

    # when
    with pytest.raises(ValidationError) as error:
        result = validator.is_valid()
        
        # then
        assert 'Text must contain at least one uppercase letter' in str(error.value)


def test_if_has_upper_character_validator_all_punctuation():
    # given
    validator = HasUpperCharacterValidator('!@#$%')

    # when
    with pytest.raises(ValidationError) as error:
        result = validator.is_valid()
        
        # then
        assert 'Text must contain at least one uppercase letter' in str(error.value)


def test_if_has_number_validator_positive():
    # given
    validator = HasNumberValidator('test1')

    # when
    result = validator.is_valid()

    # then
    assert result is True


def test_if_has_number_validator_negative():
    # given
    validator = HasNumberValidator('test')

    # when
    with pytest.raises(ValidationError) as error:
        result = validator.is_valid()
        
        # then
        assert 'Text must contain number' in str(error.value)


def test_if_has_special_charakter_validator_positive():
    # given
    validator = HasSpecialCharacterValidator('@test')

    # when
    result = validator.is_valid()

    # then
    assert result is True


def test_if_has_special_charakter_validator_negative():
    # given
    validator = HasSpecialCharacterValidator('test1')

    # when
    with pytest.raises(ValidationError) as error:
        result = validator.is_valid()
        
        # then
        assert 'Text must contain special character' in str(error.value)


def test_if_lenght_validator_8_char():
    # given
    validator = LengthValidator('testtest', 8)

    # when
    result = validator.is_valid()

    # then
    assert result is True


def test_if_lenght_validator_more_than_8_char():
    # given
    validator = LengthValidator('testtesttest', 8)

    # when
    result = validator.is_valid()

    # then
    assert result is True


def test_if_lenght_validator_less_than_8_char():
    # given
    validator = LengthValidator('test', 8)

    # when
    with pytest.raises(ValidationError) as error:
        result = validator.is_valid()
        
        # then
        assert f'Text must contain at least 8 characters' in str(error.value)


def test_if_have_been_pawd_validator_negative(requests_mock):
    #Hash dla słowa: test
    #A94A8FE5CCB19BA61C4C0873D391E987982FBBD3
    
    data = 'FE5CCB19BA61C4C0873D391E987982FBBD3:2\n\r'
    requests_mock.get('https://api.pwnedpasswords.com/range/A94A8', text=data)
    
    # given
    validator = HaveIbeenPwnedValidator('test')

    # when
    with pytest.raises(ValidationError) as error:
        result = validator.is_valid()
        
        # then
        assert 'This password have been pwned' in str(error.value)


def test_if_have_been_pawd_validator_positive(requests_mock):

    data = 'FE5CCB19BA61C4C0873D391E987982F3333:2\n\r'
    requests_mock.get('https://api.pwnedpasswords.com/range/A94A8', text=data)
    
    # given
    validator = HaveIbeenPwnedValidator('test')

    # when
    result = validator.is_valid()

    # then
    assert result is True


def test_password_validator_positive():
    # given
    validator = PasswordValidator('test1234')

    # when
    with pytest.raises(ValidationError) as error:
        result = validator.is_valid()
        
        # then
        assert 'Text must contain special character' in str(error.value)