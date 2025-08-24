package models

import (
	"strings"
	"time"

	"gorm.io/gorm"
)

type User struct {
	ID             int            `gorm:"type:int;primaryKey;autoIncrement" json:"id"`
	Email          string         `gorm:"type:varchar(255);uniqueIndex;not null" json:"email"`
	HashedPassword string         `gorm:"type:varchar(255);not null" json:"hashed_password"`
	MFA            bool           `gorm:"default:false" json:"mfa"`
	TempCode       string         `gorm:"type:varchar(255);index" json:"temp_code"` // Temporary code for authentication steps
	UserCode       string         `gorm:"type:varchar(200)" json:"user_code"`
	OTPSecret      string         `gorm:"type:varchar(255)" json:"otp_secret"` // For TOTP/HOTP implementation (optional)
	CreatedAt      time.Time      `gorm:"default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt      time.Time      `gorm:"default:CURRENT_TIMESTAMP" json:"updated_at"`
	DeletedAt      gorm.DeletedAt `gorm:"index" json:"-"` // For soft deletes (optional)
}

// Hook: force lowercase email before insert
func (u *User) BeforeCreate(tx *gorm.DB) (err error) {
	u.Email = strings.ToLower(u.Email)
	return
}

// Hook: force lowercase email before update
func (u *User) BeforeUpdate(tx *gorm.DB) (err error) {
	u.Email = strings.ToLower(u.Email)
	return
}
