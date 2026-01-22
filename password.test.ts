import { describe, test, expect } from '@jest/globals';

/**
 * Password validation utility functions
 */
class PasswordValidator {
  /**
   * Check if password meets minimum length requirement
   */
  static hasMinimumLength(password: string, minLength: number = 8): boolean {
    return password.length >= minLength;
  }

  /**
   * Check if password contains at least one uppercase letter
   */
  static hasUpperCase(password: string): boolean {
    return /[A-Z]/.test(password);
  }

  /**
   * Check if password contains at least one lowercase letter
   */
  static hasLowerCase(password: string): boolean {
    return /[a-z]/.test(password);
  }

  /**
   * Check if password contains at least one number
   */
  static hasNumber(password: string): boolean {
    return /\d/.test(password);
  }

  /**
   * Check if password contains at least one special character
   */
  static hasSpecialChar(password: string): boolean {
    return /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);
  }

  /**
   * Comprehensive password validation
   */
  static isValid(password: string): boolean {
    return (
      this.hasMinimumLength(password) &&
      this.hasUpperCase(password) &&
      this.hasLowerCase(password) &&
      this.hasNumber(password) &&
      this.hasSpecialChar(password)
    );
  }

  /**
   * Get password strength score (0-5)
   */
  static getStrength(password: string): number {
    let strength = 0;
    if (this.hasMinimumLength(password)) strength++;
    if (this.hasUpperCase(password)) strength++;
    if (this.hasLowerCase(password)) strength++;
    if (this.hasNumber(password)) strength++;
    if (this.hasSpecialChar(password)) strength++;
    return strength;
  }
}

describe('Password Validator', () => {
  describe('hasMinimumLength', () => {
    test('should return true for passwords with 8 or more characters', () => {
      expect(PasswordValidator.hasMinimumLength('12345678')).toBe(true);
      expect(PasswordValidator.hasMinimumLength('abcdefghij')).toBe(true);
    });

    test('should return false for passwords with less than 8 characters', () => {
      expect(PasswordValidator.hasMinimumLength('1234567')).toBe(false);
      expect(PasswordValidator.hasMinimumLength('abc')).toBe(false);
      expect(PasswordValidator.hasMinimumLength('')).toBe(false);
    });

    test('should respect custom minimum length', () => {
      expect(PasswordValidator.hasMinimumLength('12345', 5)).toBe(true);
      expect(PasswordValidator.hasMinimumLength('1234', 5)).toBe(false);
    });
  });

  describe('hasUpperCase', () => {
    test('should return true for passwords with uppercase letters', () => {
      expect(PasswordValidator.hasUpperCase('Password')).toBe(true);
      expect(PasswordValidator.hasUpperCase('ABC')).toBe(true);
      expect(PasswordValidator.hasUpperCase('aBc')).toBe(true);
    });

    test('should return false for passwords without uppercase letters', () => {
      expect(PasswordValidator.hasUpperCase('password')).toBe(false);
      expect(PasswordValidator.hasUpperCase('123456')).toBe(false);
      expect(PasswordValidator.hasUpperCase('')).toBe(false);
    });
  });

  describe('hasLowerCase', () => {
    test('should return true for passwords with lowercase letters', () => {
      expect(PasswordValidator.hasLowerCase('Password')).toBe(true);
      expect(PasswordValidator.hasLowerCase('abc')).toBe(true);
      expect(PasswordValidator.hasLowerCase('ABc')).toBe(true);
    });

    test('should return false for passwords without lowercase letters', () => {
      expect(PasswordValidator.hasLowerCase('PASSWORD')).toBe(false);
      expect(PasswordValidator.hasLowerCase('123456')).toBe(false);
      expect(PasswordValidator.hasLowerCase('')).toBe(false);
    });
  });

  describe('hasNumber', () => {
    test('should return true for passwords with numbers', () => {
      expect(PasswordValidator.hasNumber('Password1')).toBe(true);
      expect(PasswordValidator.hasNumber('123')).toBe(true);
      expect(PasswordValidator.hasNumber('abc123')).toBe(true);
    });

    test('should return false for passwords without numbers', () => {
      expect(PasswordValidator.hasNumber('Password')).toBe(false);
      expect(PasswordValidator.hasNumber('abc')).toBe(false);
      expect(PasswordValidator.hasNumber('')).toBe(false);
    });
  });

  describe('hasSpecialChar', () => {
    test('should return true for passwords with special characters', () => {
      expect(PasswordValidator.hasSpecialChar('Password!')).toBe(true);
      expect(PasswordValidator.hasSpecialChar('@#$%')).toBe(true);
      expect(PasswordValidator.hasSpecialChar('abc@123')).toBe(true);
    });

    test('should return false for passwords without special characters', () => {
      expect(PasswordValidator.hasSpecialChar('Password1')).toBe(false);
      expect(PasswordValidator.hasSpecialChar('abc123')).toBe(false);
      expect(PasswordValidator.hasSpecialChar('')).toBe(false);
    });
  });

  describe('isValid', () => {
    test('should return true for valid passwords', () => {
      expect(PasswordValidator.isValid('Password123!')).toBe(true);
      expect(PasswordValidator.isValid('SecureP@ss1')).toBe(true);
      expect(PasswordValidator.isValid('MyP@ssw0rd')).toBe(true);
    });

    test('should return false for invalid passwords', () => {
      expect(PasswordValidator.isValid('password')).toBe(false); // no uppercase, number, special char
      expect(PasswordValidator.isValid('PASSWORD123!')).toBe(false); // no lowercase
      expect(PasswordValidator.isValid('Password!')).toBe(false); // no number
      expect(PasswordValidator.isValid('Password123')).toBe(false); // no special char
      expect(PasswordValidator.isValid('Pass1!')).toBe(false); // too short
      expect(PasswordValidator.isValid('')).toBe(false); // empty
    });
  });

  describe('getStrength', () => {
    test('should return 0 for empty password', () => {
      expect(PasswordValidator.getStrength('')).toBe(0);
    });

    test('should return 1 for very weak password', () => {
      expect(PasswordValidator.getStrength('abc')).toBe(1); // only lowercase
      expect(PasswordValidator.getStrength('ABC')).toBe(1); // only uppercase
    });

    test('should return 2 for password with length and one criteria', () => {
      expect(PasswordValidator.getStrength('abcdefgh')).toBe(2); // length + lowercase
      expect(PasswordValidator.getStrength('ABCDEFGH')).toBe(2); // length + uppercase
    });

    test('should return 5 for password meeting all criteria', () => {
      expect(PasswordValidator.getStrength('Password123!')).toBe(5);
      expect(PasswordValidator.getStrength('SecureP@ss1')).toBe(5);
    });

    test('should return correct strength for partial passwords', () => {
      expect(PasswordValidator.getStrength('Pass1!')).toBe(4); // missing length
      expect(PasswordValidator.getStrength('password123')).toBe(3); // missing uppercase and special char
    });
  });
});
