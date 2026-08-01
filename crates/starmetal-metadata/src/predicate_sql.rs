//! Compilation of a [`QueryPredicate`] into a parameterized Postgres `WHERE` fragment
//! (ADR-0022 selector push-down).
//!
//! The authorizer hands callers an abstract [`QueryPredicate`]; the browse path compiles it here
//! into a boolean SQL expression over the `components` table plus its ordered bind parameters. Every
//! value becomes a `$n` placeholder — nothing is ever interpolated into the SQL string, so the
//! compiled fragment is injection-safe regardless of grant contents.

use starmetal_core::authz::{NamePattern, QueryPredicate};

/// A compiled boolean `WHERE` fragment and its ordered `$1..` bind parameters.
///
/// `sql` references parameters positionally (`$1`, `$2`, ...); `params` supplies their values in
/// the same order. Callers that append further placeholders (e.g. `LIMIT`/`OFFSET`) continue
/// numbering from `params.len() + 1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledPredicate {
    /// The boolean SQL expression (always a valid standalone `WHERE` body — never empty).
    pub sql: String,
    /// Bind values for the `$1..` placeholders in `sql`, in order.
    pub params: Vec<String>,
}

/// Compile `predicate` into a parameterized `WHERE` fragment over the `components` table.
pub fn compile(predicate: &QueryPredicate) -> CompiledPredicate {
    let mut params = Vec::new();
    let sql = compile_into(predicate, &mut params);
    CompiledPredicate { sql, params }
}

fn placeholder(params: &mut Vec<String>, value: String) -> String {
    params.push(value);
    format!("${}", params.len())
}

fn compile_into(predicate: &QueryPredicate, params: &mut Vec<String>) -> String {
    match predicate {
        QueryPredicate::Always => "TRUE".to_string(),
        QueryPredicate::Never => "FALSE".to_string(),
        QueryPredicate::Ecosystem(ecosystem) => {
            let placeholder = placeholder(params, ecosystem.to_string());
            format!("ecosystem = {placeholder}")
        }
        QueryPredicate::CoordinateName(NamePattern::Any) => "TRUE".to_string(),
        QueryPredicate::CoordinateName(NamePattern::Exact(name)) => {
            let placeholder = placeholder(params, name.clone());
            format!("name = {placeholder}")
        }
        QueryPredicate::CoordinateName(NamePattern::Prefix(prefix)) => {
            let placeholder = placeholder(params, format!("{}%", escape_like(prefix)));
            format!("name LIKE {placeholder} ESCAPE '\\'")
        }
        // The `components` table has no asset-path column, so an asset-path predicate can never
        // match a component row. It compiles fail-closed to a false constant: component browse is
        // coordinate-scoped (ADR-0022), and authorizer-produced browse predicates never carry path
        // terms anyway. ~keep
        QueryPredicate::PathPrefix(_) | QueryPredicate::PathEquals(_) => "FALSE".to_string(),
        QueryPredicate::All(children) => combine(children, params, "AND", "TRUE"),
        QueryPredicate::Any(children) => combine(children, params, "OR", "FALSE"),
        QueryPredicate::Not(child) => {
            let inner = compile_into(child, params);
            format!("(NOT ({inner}))")
        }
    }
}

fn combine(children: &[QueryPredicate], params: &mut Vec<String>, operator: &str, empty: &str) -> String {
    if children.is_empty() {
        return empty.to_string();
    }
    let parts: Vec<String> = children.iter().map(|child| compile_into(child, params)).collect();
    format!("({})", parts.join(&format!(" {operator} ")))
}

/// Escape the `LIKE` metacharacters `\`, `%`, and `_` so a name prefix matches literally (the
/// trailing `%` wildcard is appended by the caller, after escaping).
fn escape_like(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for character in input.chars() {
        if matches!(character, '\\' | '%' | '_') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

#[cfg(test)]
mod tests {
    use starmetal_core::package::Ecosystem;

    use super::*;

    #[test]
    fn always_and_never_compile_to_constants() {
        assert_eq!(compile(&QueryPredicate::Always).sql, "TRUE");
        assert!(compile(&QueryPredicate::Always).params.is_empty());
        assert_eq!(compile(&QueryPredicate::Never).sql, "FALSE");
    }

    #[test]
    fn ecosystem_binds_a_lowercase_parameter() {
        let compiled = compile(&QueryPredicate::Ecosystem(Ecosystem::Cargo));
        assert_eq!(compiled.sql, "ecosystem = $1");
        assert_eq!(compiled.params, vec!["cargo".to_string()]);
    }

    #[test]
    fn exact_name_binds_a_parameter() {
        let compiled = compile(&QueryPredicate::CoordinateName(NamePattern::Exact(
            "left-pad".to_string(),
        )));
        assert_eq!(compiled.sql, "name = $1");
        assert_eq!(compiled.params, vec!["left-pad".to_string()]);
    }

    #[test]
    fn prefix_name_escapes_like_metacharacters() {
        let compiled = compile(&QueryPredicate::CoordinateName(NamePattern::Prefix(
            "ab_c%".to_string(),
        )));
        assert_eq!(compiled.sql, "name LIKE $1 ESCAPE '\\'");
        assert_eq!(compiled.params, vec!["ab\\_c\\%%".to_string()]);
    }

    #[test]
    fn any_name_is_unconstrained() {
        assert_eq!(compile(&QueryPredicate::CoordinateName(NamePattern::Any)).sql, "TRUE");
    }

    #[test]
    fn path_predicates_fail_closed_for_component_browse() {
        assert_eq!(compile(&QueryPredicate::PathPrefix("pypi/".to_string())).sql, "FALSE");
        assert_eq!(compile(&QueryPredicate::PathEquals("pypi/x".to_string())).sql, "FALSE");
    }

    #[test]
    fn nested_all_any_number_parameters_in_order() {
        let predicate = QueryPredicate::All(vec![
            QueryPredicate::Ecosystem(Ecosystem::Npm),
            QueryPredicate::Any(vec![
                QueryPredicate::CoordinateName(NamePattern::Exact("a".to_string())),
                QueryPredicate::CoordinateName(NamePattern::Exact("b".to_string())),
            ]),
        ]);
        let compiled = compile(&predicate);
        assert_eq!(compiled.sql, "(ecosystem = $1 AND (name = $2 OR name = $3))");
        assert_eq!(
            compiled.params,
            vec!["npm".to_string(), "a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn empty_conjunction_and_disjunction_have_identity_constants() {
        assert_eq!(compile(&QueryPredicate::All(vec![])).sql, "TRUE");
        assert_eq!(compile(&QueryPredicate::Any(vec![])).sql, "FALSE");
    }

    #[test]
    fn not_wraps_its_child() {
        let compiled = compile(&QueryPredicate::Not(Box::new(QueryPredicate::Ecosystem(
            Ecosystem::Hex,
        ))));
        assert_eq!(compiled.sql, "(NOT (ecosystem = $1))");
        assert_eq!(compiled.params, vec!["hex".to_string()]);
    }
}
