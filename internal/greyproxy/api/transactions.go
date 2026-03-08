package api

import (
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
)

func TransactionsListHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
		offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

		f := greyproxy.TransactionFilter{
			Container:   c.Query("container"),
			Destination: c.Query("destination"),
			Method:      c.Query("method"),
			Limit:       limit,
			Offset:      offset,
		}

		if v := c.Query("from_date"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				f.FromDate = &t
			} else if t, err := time.Parse("2006-01-02T15:04", v); err == nil {
				f.FromDate = &t
			}
		}
		if v := c.Query("to_date"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				f.ToDate = &t
			} else if t, err := time.Parse("2006-01-02T15:04", v); err == nil {
				f.ToDate = &t
			}
		}

		items, total, err := greyproxy.QueryHttpTransactions(s.DB, f)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		jsonItems := make([]greyproxy.HttpTransactionJSON, len(items))
		for i, item := range items {
			jsonItems[i] = item.ToJSON(false)
		}

		page := 1
		if limit > 0 && offset > 0 {
			page = offset/limit + 1
		}
		pages := 1
		if limit > 0 && total > 0 {
			pages = int(math.Ceil(float64(total) / float64(limit)))
		}

		c.JSON(http.StatusOK, gin.H{
			"items": jsonItems,
			"total": total,
			"page":  page,
			"pages": pages,
		})
	}
}

func TransactionsDetailHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}

		txn, err := greyproxy.GetHttpTransaction(s.DB, id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if txn == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "transaction not found"})
			return
		}

		c.JSON(http.StatusOK, txn.ToJSON(true))
	}
}
