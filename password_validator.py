"""Collection of password validator"""
from abc import ABC, abstractmethod
from hashlib import sha1
import string
from requests import get


class ValidationError(Exception):
    """Exception for validation error"""


class ValidatorInterface(ABC):
    """Interface for validators"""

    @abstractmethod
    def __init__(self, text: str):
        """Force to implement __init__ metod in child classes

        Args:
            text (str): text that will be validated
        """

    @abstractmethod
    def is_valid(self):
        """Force to implement is_valid metod in child classes"""


class LengthValidator(ValidatorInterface):
    """Validator to check text length"""

    def __init__(self, text, min_length=8) -> None:
        self.text = text
        self.min_length = min_length

    def is_valid(self) -> bool:
        """Check if text is valid

        Raises:
            ValidationError: text has no at least minimum length

        Returns:
            bool: return True if text has more than minimum length
        """
        if len(self.text) >= self.min_length:
            return True
        raise ValidationError(f'Text must contain at least {self.min_length} characters')


class HasNumberValidator(ValidatorInterface):
    """Validator to check text has number"""

    def __init__(self, text) -> None:
        self.text = text

    def is_valid(self):
        """Check if text is valid

        Raises:
            ValidationError: text has no number

        Returns:
            bool: return True if text has number
        """
        if any(char in string.digits for char in self.text):
            return True
        raise ValidationError('Text must contain number')


class HasSpecialCharacterValidator(ValidatorInterface):
    """Validator to check text has special character"""

    def __init__(self, text) -> None:
        self.text = text

    def is_valid(self):
        """Check if text is valid

        Raises:
            ValidationError: text has no special character

        Returns:
            bool: return True if text has special character
        """
        if any(char in string.punctuation for char in self.text):
            return True
        raise ValidationError('Text must contain special character')


class HasUpperCharacterValidator(ValidatorInterface):
    """Validator to check text has uppercase letter"""

    def __init__(self, text) -> None:
        self.text = text

    def is_valid(self):
        """Check if text is valid

        Raises:
            ValidationError: text has no uppercase letter

        Returns:
            bool: return True if text has uppercase letter
        """
        if any(char in string.ascii_uppercase for char in self.text):
            return True
        raise ValidationError('Text must contain at least one uppercase letter')


class HasLowerCharacterValidator(ValidatorInterface):
    """Validator to check text has lowercase letter"""

    def __init__(self, text) -> None:
        self.text = text

    def is_valid(self):
        """Check if text is valid

        Raises:
            ValidationError: text has no lowercase letter

        Returns:
            bool: return True if text has lowercase letter
        """
        if any(char in string.ascii_lowercase for char in self.text):
            return True
        raise ValidationError('Text must contain at least one lowercase letter')


class HaveIbeenPwnedValidator(ValidatorInterface):
    """Validator to check text has been pwned"""

    def __init__(self, text:str) -> None:
        self.text = text
        self._api_url = 'https://api.pwnedpasswords.com/range/'

    @staticmethod
    def str_to_hash(text:str) -> str:
        """Converting string to hash

        Args:
            text (str): text to be converted to hash

        Returns:
            str: hash as hexadecimal digits
        """
        hash_value = sha1(text.encode('utf-8'))
        return hash_value.hexdigest()

    def is_valid(self) -> None:
        """Check if text is valid

        Raises:
            ValidationError: text has been pwned

        Returns:
            bool: return True if text has not been pwned
        """
        hash_value = self.str_to_hash(self.text)

        with get(self._api_url+hash_value[:5]) as response:
            pwnedpasswords = response.text.splitlines()

        if not any(hash_value[5:].upper() in pwnedpassword for pwnedpassword in pwnedpasswords):
            return True

        raise ValidationError('This password have been pwned')


class PasswordValidator(ValidatorInterface):
    """Validator to check password meets all the requirements"""

    def __init__(self, password) -> None:
        self.password = password
        self.validators = [
            LengthValidator,
            HasNumberValidator,
            HasSpecialCharacterValidator,
            HasUpperCharacterValidator,
            HasLowerCharacterValidator,
            HaveIbeenPwnedValidator
        ]

    def is_valid(self):
        """Checks if password is valid

        Returns:
            bool: return True if password meets all the requirements
        """
        for class_name in self.validators:
            validator = class_name(self.password)
            validator.is_valid()
        return True
