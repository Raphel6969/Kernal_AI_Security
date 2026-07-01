package main
import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
)
func main() {
	url := "postgres://user:aeri3107@localhost:5432/aegix"
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		fmt.Println("Config error:", err)
		os.Exit(1)
	}
	err = pool.Ping(context.Background())
	if err != nil {
		fmt.Println("Ping error:", err)
		os.Exit(1)
	}
	fmt.Println("Success!")
}
