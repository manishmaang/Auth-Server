package config

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func init() {
	var err error
	err = godotenv.Load()
	if err != nil{
		log.Fatal("Could not load the env file, error is : ", err.Error());
		return;
	}

	db_url := os.Getenv("DB_URL")
	DB, err = gorm.Open(postgres.Open(db_url), &gorm.Config{})

	if err != nil {
		fmt.Println("Error while connecting to the database, error is : ", err.Error())
		return
	}

	sqlDB, err := DB.DB()
	if err != nil {
		fmt.Println("Error while getting the database instance, error is : ", err.Error())
		return
	}

	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetMaxOpenConns(50)

	fmt.Println("Successfully connected to the database")
}

func EnvValue(env_varibale string) (string) {
	return os.Getenv(env_varibale)
}
