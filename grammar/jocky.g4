// JOCKY Grammar - ANTLR4 - Independent Language + Investigation Blocks (LANGUAGE_SPEC §11)
// Syntax: investigation "host_scan" { system.info(); } | process.list(); file.hash("a.exe"); system.info(); driver.scan("RTCore64.sys");
grammar jocky;

program : statement* EOF ;

statement
  : investigationStmt
  | varDecl
  | assignment
  | exprStmt
  | ifStmt
  | forStmt
  | whileStmt
  | funcDecl
  | returnStmt
  | importStmt
  ;

investigationStmt : 'investigation' STRING block ;
importStmt : 'import' STRING ';' ;
varDecl    : 'let' ID ('=' expr)? ';' ;
assignment : ID '=' expr ';' ;
exprStmt   : expr ';' ;
returnStmt : 'return' expr? ';' ;

ifStmt   : 'if' '(' expr ')' block ('else' block)? ;
forStmt  : 'for' '(' (varDecl|exprStmt|';') expr? ';' expr? ')' block ;
whileStmt: 'while' '(' expr ')' block ;
funcDecl : 'func' ID '(' paramList? ')' block ;
paramList: ID (',' ID)* ;
block    : '{' statement* '}' ;

expr
  : expr '.' ID '(' argList? ')'   # MemberCall
  | expr '.' ID                    # MemberAccess
  | expr '[' expr ']'              # Index
  | '!' expr                       # Not
  | expr op=('*'|'/') expr         # MulDiv
  | expr op=('+'|'-') expr         # AddSub
  | expr op=('=='|'!='|'<'|'>'|'<='|'>=') expr # Compare
  | expr op=('&&'|'||') expr       # Logic
  | '(' expr ')'                   # Paren
  | ID                             # Var
  | STRING                         # Str
  | NUMBER                         # Num
  | 'true' | 'false'               # Bool
  | 'null'                         # Null
  | lambda                         # LambdaExpr
  ;

lambda  : '(' paramList? ')' '=>' (expr | block)
        | ID '=>' (expr | block) ;
argList : expr (',' expr)* ;

ID     : [a-zA-Z_][a-zA-Z0-9_]* ;
NUMBER : [0-9]+ ('.' [0-9]+)? ;
STRING : '"' (~["\r\n] | '\\' .)* '"' | '\'' (~['\r\n] | '\\' .)* '\'' ;
WS     : [ \t\r\n]+ -> skip ;
COMMENT: '//' ~[\r\n]* -> skip ;
BLOCK_COMMENT: '/*' .*? '*/' -> skip ;
