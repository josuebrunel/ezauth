package models

// UserStats are the headline user counts for a dashboard.
type UserStats struct {
	Total        int `db:"total" json:"total"`
	CreatedSince int `db:"created_since" json:"created_since"` // joined at or after the cutoff
	ActiveSince  int `db:"active_since" json:"active_since"`   // last active at or after the cutoff
	Inactive     int `db:"inactive" json:"inactive"`           // is_active is false: suspended or locked out
}

// DayCount is how many users joined on one UTC day, as YYYY-MM-DD text. Text
// keeps the result identical across the three databases, whose date types
// don't agree.
type DayCount struct {
	Day   string `db:"day" json:"day"`
	Count int    `db:"n" json:"count"`
}
