/**
 * @name Direct call to 'strcpy' (baseline demonstration)
 * @description Reports direct calls to 'strcpy' as a low-precision hypothesis only. It does not establish that an input is attacker-controlled, that the destination can overflow, or that a vulnerability or CVE exists.
 * @kind problem
 * @problem.severity warning
 * @precision low
 * @id cve2checker/direct-strcpy-call-baseline
 */
import cpp

from FunctionCall call
where call.getTarget().hasName("strcpy")
select call, "Direct call to strcpy (baseline demonstration only)."
