// Created: 2026-03-13 by Constructor Tech
// Updated: 2026-03-16 by Constructor Tech
#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_ast;

use rustc_ast::{
    AssocItemKind, Expr, ExprKind, Item, ItemKind, UnOp,
    token::LitKind,
    visit, visit::Visitor,
};
use rustc_lint::{EarlyLintPass, LintContext};

dylint_linting::declare_early_lint! {
    /// ### What it does
    ///
    /// Detects manual byte-zeroing (`*b = 0` or `.fill(0)`) inside `impl Drop`
    /// implementations, which the LLVM optimizer may legally eliminate.
    ///
    /// ### Why is this bad?
    ///
    /// The LLVM optimizer performs dead-store elimination: if it can prove that
    /// a write to memory is never read again before the memory is freed, it may
    /// remove the write entirely. Manual zeroing in `Drop::drop` is almost always
    /// a dead store from the optimizer's perspective. The `secrecy` and `zeroize`
    /// crates work around this using a compiler memory fence to prevent removal.
    ///
    /// ### Example
    ///
    /// ```rust,ignore
    /// // Bad - may be silently optimized away
    /// impl Drop for SecretKey {
    ///     fn drop(&mut self) {
    ///         self.data.fill(0);  // LLVM may remove this!
    ///     }
    /// }
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust,ignore
    /// // Good (preferred for secrets) - secrecy provides zeroization + redacted Debug
    /// use secrecy::{ExposeSecret, SecretBox};
    /// pub type SecretKey = SecretBox<Vec<u8>>;
    ///
    /// // Good (alternative) - zeroize when only wiping is needed
    /// use zeroize::Zeroize;
    /// impl Drop for SecretKey {
    ///     fn drop(&mut self) {
    ///         self.data.zeroize();
    ///     }
    /// }
    /// ```
    pub DE0707_DROP_ZEROIZE,
    Deny,
    "manual byte-zeroing in Drop may be optimized away; use `secrecy::SecretBox` or the `zeroize` crate (DE0707)"
}

/// Returns true if `expr` is the integer literal `0` (optionally typed, e.g. `0u8`).
fn is_zero_literal(expr: &Expr) -> bool {
    if let ExprKind::Lit(lit) = &expr.kind {
        lit.kind == LitKind::Integer && lit.symbol.as_str() == "0"
    } else {
        false
    }
}

struct ZeroingVisitor<'a, 'cx> {
    cx: &'a rustc_lint::EarlyContext<'cx>,
}

impl<'ast, 'a, 'cx> visit::Visitor<'ast> for ZeroingVisitor<'a, 'cx> {
    fn visit_expr(&mut self, expr: &'ast Expr) {
        match &expr.kind {
            // Pattern: *buf = 0  (deref-assign to zero)
            ExprKind::Assign(lhs, rhs, _) => {
                if matches!(&lhs.kind, ExprKind::Unary(UnOp::Deref, _))
                    && is_zero_literal(rhs)
                {
                    self.cx.span_lint(DE0707_DROP_ZEROIZE, expr.span, |diag| {
                        diag.primary_message(
                            "manual byte-zeroing in `Drop::drop` may be eliminated by the optimizer (DE0707)",
                        );
                        diag.help(
                            "use `secrecy::SecretBox` or `zeroize`: `.zeroize()` / `#[derive(ZeroizeOnDrop)]`",
                        );
                        diag.note(
                            "LLVM dead-store elimination can legally remove writes that are never read; `zeroize` uses a compiler fence to prevent this",
                        );
                    });
                }
            }
            // Pattern: slice.fill(0)
            ExprKind::MethodCall(call) => {
                if call.seg.ident.name.as_str() == "fill" {
                    if let Some(arg) = call.args.first() {
                        if is_zero_literal(arg) {
                            self.cx.span_lint(DE0707_DROP_ZEROIZE, expr.span, |diag| {
                                diag.primary_message(
                                    "manual byte-zeroing in `Drop::drop` may be eliminated by the optimizer (DE0707)",
                                );
                                diag.help(
                                    "use `secrecy::SecretBox` or `zeroize`: `.zeroize()` / `#[derive(ZeroizeOnDrop)]`",
                                );
                                diag.note(
                                    "LLVM dead-store elimination can legally remove writes that are never read; `zeroize` uses a compiler fence to prevent this",
                                );
                            });
                        }
                    }
                }
            }
            // Pattern: ptr::write_bytes(ptr, 0, len) / std::ptr::write_bytes(...)
            ExprKind::Call(func, args) => {
                if args.len() >= 2 {
                    if let Some(fill_byte) = args.get(1) {
                        if is_zero_literal(fill_byte) {
                            if let ExprKind::Path(_, path) = &func.kind {
                                if path.segments.last().is_some_and(|s| {
                                    s.ident.name.as_str() == "write_bytes"
                                }) {
                                    self.cx.span_lint(DE0707_DROP_ZEROIZE, expr.span, |diag| {
                                        diag.primary_message(
                                            "manual byte-zeroing in `Drop::drop` may be eliminated by the optimizer (DE0707)",
                                        );
                                        diag.help(
                                            "use `secrecy::SecretBox` (project standard for secrets) or `zeroize`: `.zeroize()` / `#[derive(ZeroizeOnDrop)]`",
                                        );
                                        diag.note(
                                            "LLVM dead-store elimination can legally remove writes that are never read; `zeroize` uses a compiler fence to prevent this",
                                        );
                                    });
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        // Always recurse so nested blocks (for loops, unsafe blocks, closures) are visited
        visit::walk_expr(self, expr);
    }
}

impl EarlyLintPass for De0707DropZeroize {
    fn check_item(&mut self, cx: &rustc_lint::EarlyContext<'_>, item: &Item) {
        let ItemKind::Impl(impl_block) = &item.kind else {
            return;
        };

        // Only examine `impl Drop for X` blocks
        let Some(trait_ref) = &impl_block.of_trait else {
            return;
        };
        let Some(last_seg) = trait_ref.trait_ref.path.segments.last() else {
            return;
        };
        if last_seg.ident.name.as_str() != "Drop" {
            return;
        }

        // Walk the body of `fn drop`
        for assoc_item in &impl_block.items {
            let AssocItemKind::Fn(fn_item) = &assoc_item.kind else {
                continue;
            };
            if fn_item.ident.name.as_str() != "drop" {
                continue;
            }
            let Some(body) = &fn_item.body else {
                continue;
            };

            let mut visitor = ZeroingVisitor { cx };
            visitor.visit_block(body);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn ui_examples() {
        dylint_testing::ui_test_examples(env!("CARGO_PKG_NAME"));
    }

    #[test]
    fn test_comment_annotations_match_stderr() {
        let ui_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("ui");
        lint_utils::test_comment_annotations_match_stderr(&ui_dir, "DE0707", "manual zeroing");
    }
}
