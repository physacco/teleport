package common

import (
    "time"
)

func AfterSeconds(nsecs time.Duration) time.Time {
    return time.Now().Add(time.Second * nsecs)
}
