package verifyinboxes

import "context"

// Iter walks a paged list one item at a time, asking the API for the next page only when the current one is used
// up; nothing is asked before the first [Iter.Next].
//
//	rows := client.Lists.Results(ctx, listID, nil)
//	for rows.Next() {
//		row := rows.Current()
//		...
//	}
//	if err := rows.Err(); err != nil { ... }
//
// With Go 1.23 or later, range over [Iter.All] instead:
//
//	for row, err := range client.Lists.Results(ctx, listID, nil).All() {
//		if err != nil { ... }
//		...
//	}
//
// It follows the cursor of each page until there is none, whatever a page holds (a page may hold fewer items than
// asked, even none, before the last), so every item comes once and in order. A page that fails is asked again with
// the same cursor (the client's retries). A page that sends back the very cursor it was asked with would make the
// walk go round forever, or repeat items: its items are given, then the walk stops with an error matching
// [ErrUnexpectedAnswer].
//
// Every page is asked with the context given to the method that made the Iter (such as [ListService.Results]):
// cancelling it, or its deadline passing, ends the walk at the next page asked, with that error in [Iter.Err].
//
// An Iter is not safe for use by several goroutines at once.
type Iter[T any] struct {
	ctx   context.Context
	fetch func(ctx context.Context, cursor *string) (items []T, next *string, err error)
	// sameCursor is the error of a page that sent back the cursor it was asked with.
	sameCursor func(cursor string) error

	items   []T
	index   int
	current T
	cursor  *string
	started bool
	done    bool
	pending error
	err     error
}

// failedIter is an Iter that stops at once with err (a wrong argument).
func failedIter[T any](err error) *Iter[T] { return &Iter[T]{err: err} }

// Next advances to the next item and reports whether there is one. It returns false at the end of the list and when
// a page could not be read; [Iter.Err] tells the two apart.
func (it *Iter[T]) Next() bool {
	for it.index >= len(it.items) {
		if it.err != nil || it.done {
			return false
		}
		if it.pending != nil {
			it.err = it.pending
			return false
		}
		if it.started && it.cursor == nil {
			it.done = true
			return false
		}
		sent := it.cursor
		items, next, err := it.fetch(it.ctx, sent)
		it.started = true
		if err != nil {
			it.err = err
			return false
		}
		if next != nil && sent != nil && *next == *sent {
			it.pending = it.sameCursor(*sent)
		}
		it.items, it.index, it.cursor = items, 0, next
	}
	it.current = it.items[it.index]
	it.index++
	return true
}

// Current returns the item [Iter.Next] advanced to.
func (it *Iter[T]) Current() T { return it.current }

// Err returns the error that stopped the walk, if one did.
func (it *Iter[T]) Err() error { return it.err }

// All returns the rest of the list as a range-over-func iterator (an iter.Seq2 of Go 1.23). When a page cannot be
// read, the last pair carries the error and the zero value.
func (it *Iter[T]) All() func(yield func(T, error) bool) {
	return func(yield func(T, error) bool) {
		for it.Next() {
			if !yield(it.Current(), nil) {
				return
			}
		}
		if err := it.Err(); err != nil {
			var zero T
			yield(zero, err)
		}
	}
}

// Collect reads the rest of the list into a slice. On an error it returns the items read before it, with the error.
func (it *Iter[T]) Collect() ([]T, error) {
	var out []T
	for it.Next() {
		out = append(out, it.Current())
	}
	return out, it.Err()
}
