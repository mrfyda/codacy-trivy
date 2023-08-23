//> using scala "2"
//> using lib "com.codacy::codacy-engine-scala-seed:6.1.0"
//> using lib "com.lihaoyi::os-lib:0.9.1"
//> using lib "com.lihaoyi::upickle:3.1.2"
//> using lib "com.lihaoyi::requests:0.8.0"

import com.codacy.plugins.api.results.Pattern
import com.codacy.plugins.api.results.Result
import com.codacy.plugins.api.results.Tool

import com.codacy.plugins.api._
import play.api.libs.json.Json

case class TrivySecretRule(ID: String, Category: String, Title: String, Severity: String)

implicit val trivySecretRuleRW = Json.format[TrivySecretRule]

val version = os
  .read(os.pwd / "go.mod")
  .linesIterator
  .collectFirst { case s"	github.com/aquasecurity/trivy $version" =>
    version.trim
  }
  .get

val lines = os
  .proc("go", "run", "./docgenerator/extract-secret-rules.go")
  .call()
  .out
  .lines()
  .mkString

val trivyRules = Json.fromJson[List[TrivySecretRule]](Json.parse(lines)).asOpt.get

def categoryAndSubcategoryOf(patternId: String): (Pattern.Category, Option[Pattern.Subcategory]) =
  (Pattern.Category.Security, None)

def severityOf(rule: TrivySecretRule): Result.Level =
  rule.Severity match {
    case "CRITICAL" => Result.Level.Err
    case "HIGH" => Result.Level.Err
    case "MEDIUM" => Result.Level.Warn
    case "LOW" => Result.Level.Info
    case _ => Result.Level.Err
  }

val patternSpecifications = trivyRules.map { rule =>
  val (category, subcategory) = categoryAndSubcategoryOf(rule.ID)
  Pattern.Specification(Pattern.Id(rule.ID), severityOf(rule), category, subcategory, enabled = true)
}

val patternDescriptions =
  trivyRules.map(rule => Pattern.Description(Pattern.Id(rule.ID), Pattern.Title(s"Detects ${rule.Title}"), None, None))

val specification = Tool.Specification(Tool.Name("trivy"), Some(Tool.Version(version)), patternSpecifications.toSet)

os.write.over(os.pwd / "docs" / "patterns.json", Json.prettyPrint(Json.toJson(specification)) + "\n")

os.remove.all(os.pwd / "docs" / "description")

os.write.over(
  os.pwd / "docs" / "description" / "description.json",
  Json.prettyPrint(Json.toJson(patternDescriptions)) + "\n",
  createFolders = true
)
