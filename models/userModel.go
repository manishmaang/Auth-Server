package models

import (
	"gorm.io/gorm"
	"time"
	"strings"
)

type User struct {
	ID             int            `gorm:"type:int;primaryKey;autoIncrement" json:"id"`
	Email          string         `gorm:"type:varchar(255);uniqueIndex;not null" json:"email"`
	HashedPassword string         `gorm:"type:varchar(255);not null" json:"-"`
	MFA            bool           `gorm:"default:false" json:"mfa"`
	TempCode       string         `gorm:"type:varchar(255);index" json:"-"` // Temporary code for authentication steps
	OTPSecret      string         `gorm:"type:varchar(255)" json:"-"`       // For TOTP/HOTP implementation (optional)
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
