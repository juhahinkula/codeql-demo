/**
 * @name SQL injection vulnerability
 * @description Building SQL queries using string concatenation can lead to SQL injection attacks
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @id java/sql-injection
 * @tags security
 *       external/cwe/cwe-089
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.SqlInjectionQuery
import DataFlow::PathGraph

class SQLInjectionConfig extends TaintTracking::Configuration {
  SQLInjectionConfig() { this = "SQLInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(SqlExpr sqlExpr | sqlExpr.getExpr() = sink.asExpr())
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, SQLInjectionConfig conf
where conf.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Possible SQL injection from $@.", 
    source.getNode(), "user input"