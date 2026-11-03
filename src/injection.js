// Does a piece of hidden text read like an instruction to an AI model? Text that is both hidden from
// people and addressed to a model is the signature of an indirect prompt injection.
//
// Strong signals are unmistakable (telling a model to drop its instructions, addressing it directly,
// chat-template markers, biasing an automated judgement, sending data away). Weak signals are things
// ordinary pages also say ("run the script", "open https://..."): they raise suspicion, never alone
// make a finding critical.

const STRONG = [
  [/\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|any|your|the|these|system)\b[^.\n]{0,30}\b(instructions?|prompts?|rules|directions|context|guidelines|guardrails)\b/i, "tells the model to drop its instructions"],
  [/\b(new|updated|real|actual|secret) instructions\b/i, "gives the model new instructions"],
  [/\byou are (now )?(an? )?(ai|assistant|chatbot|chatgpt|gpt|claude|gemini|copilot|llm|(large )?language model)\b/i, "addresses the model directly"],
  [/\b(note|message|instructions?|attention|important)\s*(to|for)\s*(the\s+)?(ai|llm|model|assistant|chatbot|agent|ai agent|reviewer bot|screening (tool|system)|ats)\b/i, "addresses the model directly"],
  [/\b(dear|hey|hi)\s+(ai|llm|model|assistant|chatgpt|claude|gemini|copilot)\b/i, "addresses the model directly"],
  [/\b(ai|llm|assistant|agent|model)s?\s*[:,]\s*(please\s+)?(ignore|disregard|you must|always|never|do not|don't|summari[sz]e|respond|reply|say|tell)\b/i, "addresses the model directly"],
  [/\b(system prompt|system message|developer message|hidden prompt)\b/i, "talks about the model's prompt"],
  [/<\|im_start\|>|<\|im_end\|>|\[\/?INST\]|<\/?system>|###\s*(system|instructions?)\b/i, "contains chat-template markers"],
  [/\b(do not|don't|never)\s+(mention|reveal|tell|disclose)\b[^.\n]{0,40}\b(user|reader|human|anyone|recruiter|reviewer)\b/i, "asks the model to keep something from the reader"],
  [/\b(rank|rate|score|grade|recommend|evaluate|classify|mark)\b[^.\n]{0,50}\b(candidate|applicant|resume|résumé|cv|paper|submission|application|product|review|email)\b[^.\n]{0,50}\b(top|best|highest|excellent|perfect|strong(ly)?|hire|accept|approve|safe|legitimate|positive|5 stars|10\/10)\b/i, "tries to bias an automated judgement"],
  [/\b(this (candidate|applicant) (is|would be) (an? )?(excellent|perfect|ideal|outstanding|exceptional))\b/i, "tries to bias an automated judgement"],
  [/\b(send|post|forward|email|upload|exfiltrate|leak)\b[^.\n]{0,60}\b(conversation|chat|history|password|credentials?|api key|token|secrets?|data|files?)\b[^.\n]{0,40}\b(to|at)\b[^.\n]{0,40}(https?:\/\/|www\.|[\w.-]+@[\w-]+\.)/i, "asks the model to send data somewhere"],
  [/تجاهل[^.\n]{0,40}(التعليمات|الأوامر|التوجيهات)/, "tells the model to drop its instructions (Arabic)"],
  [/(أنت الآن|انت الان)[^.\n]{0,30}(مساعد|ذكاء|نموذج)/, "addresses the model directly (Arabic)"],
];

const WEAK = [
  [/\b(run|execute)\s+(this|the following|these|that)\s+(command|script|code|program)s?\b/i, "asks for code to be run"],
  [/\b(execute|run)\b[^.\n]{0,20}\b(powershell|cmd\.exe|bash -c|curl |wget |rm -rf|invoke-expression|iex)\b/i, "asks for code to be run"],
  [/\b(click|open|visit|fetch|navigate to)\b[^.\n]{0,30}https?:\/\//i, "asks for a link to be opened"],
];

/** Reasons this text reads like an instruction to a model: { strong: [...], weak: [...] }. */
export function injectionVerdict(text) {
  const strong = [], weak = [];
  for (const [rx, why] of STRONG) if (rx.test(text) && !strong.includes(why)) strong.push(why);
  for (const [rx, why] of WEAK) if (rx.test(text) && !weak.includes(why)) weak.push(why);
  return { strong, weak };
}

/** All reasons, strongest first ([] when the text does not read like an instruction to a model). */
export function injectionSignals(text) {
  const v = injectionVerdict(text);
  return [...v.strong, ...v.weak];
}
