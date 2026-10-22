// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"regexp/syntax"
	"unicode"
	"unicode/utf8"
)

// A full-command target can constrain arguments arbitrarily. Test whether the
// RE2 program can consume a known guard-name span plus an argument separator,
// then accept some argument suffix. No shell or process inspection is used.
// Empty-width assertions depend only on start/end, ASCII word, newline and
// other-rune classes, so suffix reachability has a finite exact state space.
const maxFullTargetSteps = 32768

type targetMachine struct {
	program *syntax.Prog
	steps   int
}

func fullCommandTargetPossible(target string, exact bool) bool {
	if exact {
		target = `\A(?:` + target + `)\z`
	}
	parsed, err := syntax.Parse(`(?i)(?:`+target+`)`, syntax.Perl)
	if err != nil {
		return true
	}
	program, err := syntax.Compile(parsed.Simplify())
	if err != nil {
		return true
	}
	machine := targetMachine{program: program, steps: maxFullTargetSteps}
	for _, process := range guardProcesses {
		prefix := []rune(process.text + " ")
		for start := 0; start <= process.end-spMinOverlap; start++ {
			if exact && start != 0 {
				break
			}
			states := []uint32{uint32(program.Start)}
			previous := rune(-1)
			if start > 0 {
				previous = prefix[start-1]
			}
			for position := start; position < len(prefix) && len(states) > 0; position++ {
				var matched bool
				states, matched = machine.advance(states, previous, prefix[position])
				if machine.steps < 0 {
					return true
				}
				low, high := start, position
				if low < process.start {
					low = process.start
				}
				if high > process.end {
					high = process.end
				}
				if matched && high-low >= spMinOverlap {
					return true
				}
				previous = prefix[position]
			}
			if len(states) > 0 && machine.suffixPossible(states, previous) {
				return true
			}
		}
	}
	return false
}

// advance resolves epsilon instructions in the actual known prefix context,
// then consumes one rune. Returning a match separately preserves its span.
func (machine *targetMachine) advance(states []uint32, previous, next rune) ([]uint32, bool) {
	queue := append([]uint32(nil), states...)
	visited := make(map[uint32]bool)
	var outgoing []uint32
	matched := false
	context := syntax.EmptyOpContext(previous, next)
	for len(queue) > 0 {
		pc := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if visited[pc] {
			continue
		}
		visited[pc] = true
		machine.steps--
		if machine.steps < 0 {
			return nil, false
		}
		instruction := &machine.program.Inst[pc]
		switch instruction.Op {
		case syntax.InstAlt, syntax.InstAltMatch:
			queue = append(queue, instruction.Out, instruction.Arg)
		case syntax.InstCapture, syntax.InstNop:
			queue = append(queue, instruction.Out)
		case syntax.InstEmptyWidth:
			required := syntax.EmptyOp(instruction.Arg)
			if context&required == required {
				queue = append(queue, instruction.Out)
			}
		case syntax.InstMatch:
			matched = true
		case syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
			if instruction.MatchRune(next) {
				outgoing = append(outgoing, instruction.Out)
			}
		}
	}
	return outgoing, matched
}

const (
	targetEnd = iota
	targetWord
	targetNewline
	targetOther
)

func targetRuneClass(value rune) uint8 {
	if value < 0 {
		return targetEnd
	}
	if syntax.IsWordChar(value) {
		return targetWord
	}
	if value == '\n' {
		return targetNewline
	}
	return targetOther
}

func classRune(class uint8) rune {
	return []rune{-1, 'a', '\n', '-'}[class]
}

type targetState struct {
	pc             uint32
	previous, next uint8
}

func (machine *targetMachine) suffixPossible(states []uint32, previous rune) bool {
	var queue []targetState
	for _, pc := range states {
		for next := uint8(targetEnd); next <= targetOther; next++ {
			queue = append(queue, targetState{pc: pc, previous: targetRuneClass(previous), next: next})
		}
	}
	visited := make(map[targetState]bool)
	for len(queue) > 0 {
		state := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if visited[state] {
			continue
		}
		visited[state] = true
		machine.steps--
		if machine.steps < 0 {
			return true // unsupported complexity fails closed, like target budgets
		}
		instruction := &machine.program.Inst[state.pc]
		push := func(pc uint32) {
			queue = append(queue, targetState{pc: pc, previous: state.previous, next: state.next})
		}
		switch instruction.Op {
		case syntax.InstAlt, syntax.InstAltMatch:
			push(instruction.Out)
			push(instruction.Arg)
		case syntax.InstCapture, syntax.InstNop:
			push(instruction.Out)
		case syntax.InstEmptyWidth:
			context := syntax.EmptyOpContext(classRune(state.previous), classRune(state.next))
			required := syntax.EmptyOp(instruction.Arg)
			if context&required == required {
				push(instruction.Out)
			}
		case syntax.InstMatch:
			return true
		case syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
			if state.next != targetEnd && instructionAcceptsClass(instruction, state.next) {
				for next := uint8(targetEnd); next <= targetOther; next++ {
					queue = append(queue, targetState{pc: instruction.Out, previous: state.next, next: next})
				}
			}
		}
	}
	return false
}

func instructionAcceptsClass(instruction *syntax.Inst, class uint8) bool {
	if class == targetNewline {
		return instruction.MatchRune('\n')
	}
	if class == targetWord {
		for _, candidate := range "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz" {
			if instruction.MatchRune(candidate) {
				return true
			}
		}
		return false
	}
	if instruction.Op == syntax.InstRuneAny || instruction.Op == syntax.InstRuneAnyNotNL {
		return true
	}
	validOther := func(value rune) bool {
		// argv cannot contain NUL; invalid UTF-8 is represented by RuneError.
		return value != 0 && utf8.ValidRune(value) && targetRuneClass(value) == targetOther
	}
	if len(instruction.Rune) == 1 {
		first := instruction.Rune[0]
		if validOther(first) {
			return true
		}
		if instruction.Arg&uint32(syntax.FoldCase) != 0 {
			for candidate := unicode.SimpleFold(first); candidate != first; candidate = unicode.SimpleFold(candidate) {
				if validOther(candidate) {
					return true
				}
			}
		}
		return false
	}
	for index := 0; index+1 < len(instruction.Rune); index += 2 {
		low, high := instruction.Rune[index], instruction.Rune[index+1]
		if low == 0 {
			low++
		}
		for low <= high {
			if validOther(low) {
				return true
			}
			if low >= 0xD800 && low <= 0xDFFF {
				low = 0xE000
			} else {
				low++
			}
		}
	}
	return false
}
