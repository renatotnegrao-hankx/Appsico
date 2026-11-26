/* Fichas de anamnese do Appsico.
   - Adultos (18+): "Anamnese Psicológica Clínica — Adultos (18+)"
   - Infantojuvenil (3 a 17 anos): "Ficha de Anamnese Psicológica Infantojuvenil (3 a 17 anos)"
   A ficha é escolhida pela idade do paciente. As respostas de cada ficha ficam guardadas
   separadamente em p.anamnese.resp[modelo], criptografadas junto com o resto do prontuário.
   Item: 'pergunta' (texto livre) ou { q, op: [opções], m: 1 (várias), t: 1 (opções + texto), pf: campo do cadastro, h: dica, tipo: 'date' } */
(function () {
  const SN = ['Sim', 'Não'];
  const FICHAS = {
    adulto: {
      nome: 'Adultos (18+)', titulo: 'Anamnese Psicológica Clínica — Adultos (18+)',
      sub: 'Instrumento de entrevista e investigação clínica',
      secoes: [
        { t: 'Identificação da entrevista', itens: [
          { q: 'Data da entrevista', tipo: 'date', pf: 'hoje' },
          { q: 'Modalidade', op: ['Presencial', 'Online'] },
          { q: 'Tipo de atendimento', op: ['Individual', 'Outro'], t: 1 }] },
        { t: '1. Dados pessoais e identificação', itens: [
          { q: 'Nome completo', pf: 'nome' }, 'Nome social (se aplicável)', { q: 'Data de nascimento', pf: 'nascimento' }, { q: 'Idade', pf: 'idade' },
          'Sexo atribuído ao nascimento (quando clinicamente pertinente)', 'Identidade de gênero', 'Orientação sexual (opcional)', 'Estado civil',
          'Naturalidade', 'Nacionalidade', { q: 'Endereço', pf: 'endereco' }, { q: 'Cidade/Estado', pf: 'cidade' }, { q: 'Telefone', pf: 'telefone' }, { q: 'E-mail', pf: 'email' },
          'Pessoa de referência para contato em situações de emergência', 'Grau de parentesco', 'Telefone de emergência', 'Com quem reside atualmente?',
          'Possui filhos? Quantos? Idades?', 'Possui alguma responsabilidade de cuidado por terceiros?'] },
        { t: '2. Motivo da procura e queixa principal', itens: [
          'O que o levou a procurar atendimento psicológico neste momento?', 'Qual é a principal dificuldade ou situação que deseja trabalhar?',
          'Quando percebeu o início dessa dificuldade?', 'O que estava acontecendo em sua vida quando ela começou?',
          'A situação acontece continuamente ou em determinados momentos?', 'Quais são os fatores que parecem agravar ou aliviar o problema?',
          'Já buscou ajuda anteriormente?', 'O que espera alcançar com a psicoterapia?', 'Como acredita que a terapia poderá ajudá-lo?',
          'Existe alguma situação urgente que precisa ser abordada inicialmente?'] },
        { t: '3. Histórico pessoal e familiar', itens: [
          'Como descreveria sua infância?', 'Como era o relacionamento com seus pais ou cuidadores?', 'Como era a dinâmica familiar?',
          'Havia demonstrações de afeto, diálogo e apoio?', 'Como eram estabelecidos os limites e as regras?',
          'Houve separações, perdas, abandonos ou mudanças significativas?', 'Como é atualmente o relacionamento com os familiares?',
          'Existem conflitos familiares recorrentes?',
          { q: 'Há histórico familiar de:', op: ['Transtornos psicológicos ou psiquiátricos', 'Dependência química', 'Alcoolismo', 'Suicídio ou tentativas de suicídio', 'Doenças neurológicas', 'Doenças crônicas'], m: 1, t: 1, h: 'Quem na família e observações' },
          'Como percebe a influência da sua história familiar na pessoa que é hoje?'] },
        { t: '4. Desenvolvimento e trajetória de vida', nota: 'Investigar os principais acontecimentos e experiências ao longo das etapas do desenvolvimento.', itens: [
          'Infância — memórias significativas', 'Infância — relações com familiares e outras crianças', 'Infância — experiências de segurança ou insegurança',
          'Infância — vivências de violência, negligência ou abuso', 'Infância — brincadeiras, interesses e comportamento',
          'Adolescência — construção da identidade e autonomia', 'Adolescência — relacionamentos e amizades', 'Adolescência — experiências escolares',
          'Adolescência — sexualidade e afetividade', 'Adolescência — conflitos familiares', 'Adolescência — situações de risco ou experiências traumáticas',
          'Vida adulta — principais mudanças e conquistas', 'Vida adulta — relacionamentos afetivos', 'Vida adulta — independência e autonomia',
          'Vida adulta — experiências profissionais', 'Vida adulta — responsabilidades familiares', 'Vida adulta — perdas, frustrações e transições importantes',
          'Vida adulta — projetos e expectativas para o futuro'] },
        { t: '5. Saúde física e histórico médico', itens: [
          'Como considera sua saúde física atualmente?', 'Possui alguma doença diagnosticada?', 'Realiza acompanhamento médico?',
          'Faz uso de medicamentos? Quais, doses e horários?', 'Já passou por cirurgias ou internações?', 'Possui alergias?', 'Como está sua qualidade do sono?',
          'Como é sua alimentação?', 'Pratica atividade física? Qual frequência?', 'Apresenta dores ou sintomas físicos recorrentes?',
          'Possui alterações hormonais ou metabólicas relevantes?', 'Como avalia sua disposição física e energia diária?',
          'Possui alguma condição de saúde que interfira em sua rotina?'] },
        { t: '6. Saúde mental e histórico psicológico', itens: [
          'Já realizou psicoterapia anteriormente?', 'Quando e por quanto tempo?', 'Qual foi o motivo do acompanhamento?',
          'Já recebeu diagnóstico psicológico ou psiquiátrico?', 'Já realizou acompanhamento psiquiátrico?', 'Faz ou já fez uso de medicação psicotrópica?',
          'Já teve crises de ansiedade ou pânico?', 'Apresenta tristeza persistente ou perda de interesse?', 'Tem dificuldades de concentração ou memória?',
          'Apresenta pensamentos recorrentes ou intrusivos?', 'Tem dificuldade para controlar impulsos?', 'Apresenta alterações significativas de humor?',
          'Como costuma reagir diante de situações de estresse?', 'Já vivenciou situações traumáticas?', 'Já apresentou comportamento de automutilação?',
          'Já teve pensamentos de morte ou suicídio?', 'Já realizou alguma tentativa de suicídio?'] },
        { t: 'Avaliação de segurança e risco clínico', risco: 1,
          nota: 'Investigar diretamente, com acolhimento e sem julgamentos. Respostas positivas relacionadas a risco de suicídio, autolesão ou violência exigem avaliação específica, registro clínico e adoção das medidas de proteção e encaminhamento pertinentes. Não devem ser tratadas apenas como itens de histórico.', itens: [
          'Ideação suicida atual ou recente', 'Existência de planejamento, intenção e acesso a meios', 'Histórico de tentativas anteriores',
          'Comportamentos autolesivos', 'Risco de violência contra terceiros', 'Fatores de proteção e rede de apoio'] },
        { t: '7. Aspectos emocionais, cognitivos e comportamentais', nota: 'Avaliar como a pessoa percebe, interpreta e responde às situações do cotidiano.', itens: [
          'Como costuma expressar suas emoções?', 'Tem facilidade para identificar o que sente?', 'Como lida com frustrações?', 'Como reage a críticas?',
          'Consegue lidar com mudanças inesperadas?', 'Apresenta dificuldade para tomar decisões?', 'Costuma antecipar problemas ou imaginar cenários negativos?',
          'Como está sua autoestima?', 'Como percebe sua autoconfiança?', 'Consegue estabelecer limites?', 'Tem dificuldade para dizer não?',
          'Como administra conflitos?', 'Costuma agir por impulso?', 'Como avalia sua capacidade de organização?',
          'Apresenta dificuldades de atenção, concentração ou planejamento?'] },
        { t: '8. Relacionamentos afetivos e sexualidade', itens: [
          'Está atualmente em um relacionamento?', 'Como descreveria sua relação afetiva?', 'Como é a comunicação com o parceiro ou parceira?',
          'Existem conflitos recorrentes?', 'Como lida com ciúmes, confiança e insegurança?', 'Como costuma demonstrar afeto?', 'Como percebe sua vida sexual?',
          'Está satisfeito(a) com sua vida afetiva e sexual?', 'Existem dificuldades relacionadas à intimidade?',
          'Já vivenciou relacionamentos abusivos ou situações de violência?', 'Como percebe seus padrões de relacionamento?'] },
        { t: '9. Contexto social e rede de apoio', itens: [
          'Possui amigos próximos?', 'Com que frequência mantém contato com amigos?', 'Participa de grupos sociais?',
          'Participa de atividades culturais, esportivas ou comunitárias?', 'Possui rede de apoio emocional?', 'Sente-se pertencente aos ambientes que frequenta?',
          'Como é sua relação com a comunidade?', 'Costuma se isolar socialmente?', 'Como utiliza redes sociais e meios digitais?',
          'Existem situações de discriminação, preconceito ou exclusão em sua vida?', 'Como avalia sua satisfação com a vida social?'] },
        { t: '10. Escolaridade e desenvolvimento educacional', itens: [
          { q: 'Qual é a escolaridade atual?', op: ['Ensino fundamental', 'Ensino médio', 'Técnico', 'Superior', 'Pós-graduação'], t: 1 },
          'Curso ou formação', 'Instituição', { q: 'Formação concluída ou em andamento?', op: ['Concluída', 'Em andamento', 'Interrompida'] },
          'Possui cursos complementares?', 'Tem interesse em continuar estudando?', 'Como foi seu desempenho escolar?', 'Apresentou dificuldades de aprendizagem?',
          'Teve dificuldades de atenção, leitura, escrita ou matemática?', 'Como era sua relação com professores e colegas?',
          'Houve interrupções ou abandono escolar?', 'Possui planos de desenvolvimento acadêmico ou profissional?'] },
        { t: '11. Vida profissional e ocupacional', itens: [
          { q: 'Está trabalhando atualmente?', op: SN, t: 1 }, { q: 'Qual é sua profissão?', pf: 'profissao' }, 'Qual é sua função atual?', 'Há quanto tempo trabalha na área?',
          { q: 'Possui vínculo formal ou informal?', op: ['Formal', 'Informal', 'Autônomo', 'Não se aplica'] }, 'Qual é sua jornada de trabalho?', 'Como avalia sua satisfação profissional?',
          'Como é seu relacionamento com colegas e gestores?', 'Sente-se valorizado profissionalmente?', 'Possui dificuldades relacionadas à produtividade?',
          'Apresenta sintomas de estresse ou esgotamento profissional?', 'Já vivenciou desemprego ou instabilidade profissional?', 'Quais são seus objetivos de carreira?',
          'Como equilibra trabalho e vida pessoal?'] },
        { t: '12. Situação financeira e organização econômica', nota: 'Esta seção deve ser conduzida com respeito, sem julgamentos e considerando a realidade socioeconômica da pessoa.', itens: [
          'Como avalia sua situação financeira atual?', 'Possui renda própria?', 'Qual é a principal fonte de renda?', { q: 'A renda é fixa ou variável?', op: ['Fixa', 'Variável'] },
          'Contribui financeiramente com familiares?', 'Possui dependentes financeiros?', 'Como organiza suas despesas?', 'Consegue manter suas necessidades básicas?',
          'Possui dívidas ou compromissos financeiros?', 'Tem dificuldades para controlar gastos?', 'Consegue poupar ou realizar investimentos?', 'Possui planejamento financeiro?',
          'A situação financeira provoca ansiedade ou sofrimento?', 'Já vivenciou períodos de desemprego ou vulnerabilidade econômica?',
          'Quais são suas principais preocupações financeiras?', 'Como a condição financeira interfere em seus projetos de vida?',
          'Dados complementares — renda mensal aproximada', 'Dados complementares — despesas fixas',
          { q: 'Dados complementares — moradia', op: ['Própria', 'Alugada', 'Compartilhada'] }, 'Dados complementares — dependência financeira',
          'Dados complementares — reserva financeira', 'Dados complementares — comprometimentos financeiros relevantes'] },
        { t: '13. Hábitos, rotina e estilo de vida', itens: [
          'Como é sua rotina diária?', 'Qual horário costuma acordar e dormir?', 'Como organiza suas atividades?', 'Tem momentos de lazer?', 'Quais são seus hobbies e interesses?',
          'Consome bebidas alcoólicas?', 'Faz uso de tabaco ou nicotina?', 'Faz uso de substâncias psicoativas?', 'Com que frequência?',
          'Como utiliza a internet e dispositivos eletrônicos?', 'Tem dificuldade para equilibrar obrigações e descanso?', 'Como avalia a qualidade geral de sua rotina?'] },
        { t: '14. Espiritualidade, valores e crenças', itens: [
          'Possui alguma crença religiosa ou espiritual?', 'Participa de alguma comunidade religiosa?', 'Quais valores considera fundamentais em sua vida?',
          'O que considera importante para sua existência?', 'Quais princípios orientam suas decisões?', 'A espiritualidade ou as crenças funcionam como fonte de apoio?',
          'Existem conflitos entre seus valores pessoais e seu contexto de vida?'] },
        { t: '15. Autonomia, funcionalidade e independência', nota: 'Avaliar a capacidade de funcionamento da pessoa em diferentes áreas da vida adulta.', itens: [
          { q: 'Autocuidado', h: 'Higiene, alimentação e cuidados pessoais' }, { q: 'Vida doméstica', h: 'Organização da casa e tarefas cotidianas' },
          { q: 'Autonomia financeira', h: 'Administração de recursos e despesas' }, { q: 'Mobilidade', h: 'Deslocamento e acesso a serviços' },
          { q: 'Trabalho', h: 'Responsabilidade e desempenho ocupacional' }, { q: 'Socialização', h: 'Manutenção de vínculos e relacionamentos' },
          { q: 'Tomada de decisão', h: 'Capacidade de avaliar alternativas e decidir' }, { q: 'Organização', h: 'Planejamento e gerenciamento de tarefas' },
          { q: 'Autonomia emocional', h: 'Regulação emocional e enfrentamento de dificuldades' }, { q: 'Responsabilidades', h: 'Cumprimento de compromissos pessoais e sociais' },
          'Consegue realizar suas atividades diárias de forma independente?', 'Precisa de ajuda para alguma atividade?', 'Consegue administrar seus compromissos?',
          'Como lida com imprevistos?', 'Sente que possui controle sobre suas próprias decisões?', 'Quais áreas da vida apresentam maior dificuldade atualmente?'] },
        { t: '16. Recursos pessoais, potencialidades e fatores de proteção', nota: 'Esta seção busca identificar não apenas dificuldades, mas também capacidades, habilidades e recursos internos.', itens: [
          'Quais considera suas principais qualidades?', 'Quais são suas maiores habilidades?', 'O que costuma fazer bem?', 'Quais situações da vida conseguiu superar?',
          'O que lhe proporciona satisfação?', 'Quais pessoas considera importantes em sua vida?', 'Quais atividades promovem bem-estar?',
          'O que lhe ajuda a enfrentar momentos difíceis?', 'Quais são suas principais conquistas?', 'O que gostaria de desenvolver em si mesmo?'] },
        { t: '17. Expectativas e objetivos terapêuticos', itens: [
          'O que espera alcançar com a psicoterapia?', 'Quais aspectos da vida gostaria de transformar?', 'Que comportamentos gostaria de compreender ou modificar?',
          'Quais emoções gostaria de aprender a administrar melhor?', 'Quais dificuldades considera prioritárias?', 'Como perceberá que está evoluindo no processo terapêutico?',
          'O que espera do profissional que irá acompanhá-lo?', 'Está disposto(a) a participar ativamente do processo terapêutico?'] },
        { t: '18. Impressões e observações clínicas do profissional', nota: 'Preenchimento exclusivo do psicólogo.', itens: [
          'Apresentação pessoal e autocuidado', 'Atitude durante a entrevista', 'Contato visual', 'Comunicação verbal', 'Coerência e organização do discurso',
          'Orientação temporal e espacial', 'Atenção e concentração', 'Memória', 'Humor e afeto', 'Psicomotricidade', 'Pensamento (curso, forma e conteúdo)',
          'Percepção', 'Juízo crítico', 'Insight', 'Capacidade de elaboração', 'Comportamentos observados', 'Aspectos relevantes identificados'] },
        { t: '19. Síntese e formulação clínica inicial', itens: [
          'Demanda principal', 'Histórico e fatores associados', 'Fatores predisponentes', 'Fatores precipitantes', 'Fatores mantenedores', 'Fatores de proteção',
          'Áreas de funcionamento preservadas', 'Áreas que necessitam de atenção', 'Hipóteses clínicas iniciais (quando pertinentes)',
          'Necessidade de avaliação complementar ou encaminhamento', 'Plano terapêutico inicial'] }
      ]
    },
    infanto: {
      nome: 'Infantojuvenil (3 a 17 anos)', titulo: 'Ficha de Anamnese Psicológica Infantojuvenil (3 a 17 anos)',
      sub: 'Entrevista inicial com responsáveis e com a criança ou adolescente',
      secoes: [
        { t: '1. Dados da entrevista e identificação', itens: [
          { q: 'Data da entrevista', tipo: 'date', pf: 'hoje' }, 'Informante(s) e grau de parentesco', { q: 'Nome completo', pf: 'nome' },
          'Nome social / como prefere ser chamado(a)', { q: 'Data de nascimento / idade (anos e meses)', pf: 'nascidade' },
          { q: 'Sexo atribuído ao nascimento', op: ['F', 'M', 'Intersexo'] }, 'Identidade de gênero (se relatada)', 'Naturalidade / nacionalidade',
          { q: 'Endereço, telefone e e-mail de contato', pf: 'contato' },
          { q: 'Com quem reside', op: ['Pai e mãe', 'Só mãe', 'Só pai', 'Guarda compartilhada', 'Avós', 'Família reconstituída', 'Acolhimento institucional', 'Outros'], m: 1, t: 1 },
          'Situação de guarda / quem autoriza o atendimento', 'Religião ou crenças que a família considera relevantes', 'Etnia/raça autodeclarada (opcional)'] },
        { t: '2. Responsáveis, composição familiar e contexto socioeconômico', itens: [
          { q: 'Responsável 1 — nome / idade', pf: 'resp1' }, 'Responsável 1 — parentesco / vínculo com a criança', 'Responsável 1 — escolaridade',
          'Responsável 1 — profissão / ocupação e carga horária', 'Responsável 1 — estado civil / situação conjugal', { q: 'Responsável 1 — telefone / e-mail', pf: 'resp1c' },
          'Responsável 2 — nome / idade', 'Responsável 2 — parentesco / vínculo com a criança', 'Responsável 2 — escolaridade',
          'Responsável 2 — profissão / ocupação e carga horária', 'Responsável 2 — estado civil / situação conjugal', 'Responsável 2 — telefone / e-mail',
          'Irmãos e outros moradores da casa (nome, idade, parentesco)', 'Responsável legal e financeiro pelo atendimento (nome, CPF, e-mail para recibos)',
          { q: 'Moradia', op: ['Própria', 'Alugada', 'Cedida', 'Financiada'] },
          { q: 'Renda familiar aproximada', op: ['Até 2 SM', '2 a 5 SM', '5 a 10 SM', 'Acima de 10 SM'] }, 'Número de pessoas que dependem dessa renda',
          { q: 'Benefício social (BPC/LOAS, Bolsa Família, outros)', op: SN, t: 1 }, { q: 'Plano de saúde', op: SN, t: 1, h: 'Qual?' },
          'Dificuldades financeiras recentes que afetam a rotina ou o bem-estar da família',
          'Disponibilidade da família para frequência e custo do atendimento (periodicidade, valor, faltas)',
          'Rede de apoio (familiares, vizinhos, comunidade, igreja, ONG)'] },
        { t: '3. Queixa principal e demanda clínica', itens: [
          { q: 'Quem encaminhou', op: ['Demanda espontânea', 'Escola', 'Pediatra', 'Psiquiatra/Neuro', 'Conselho Tutelar/Justiça', 'Outro'], m: 1, t: 1 },
          'Queixa principal (nas palavras dos responsáveis)', 'Início, frequência, duração e evolução dos sintomas',
          'Situações em que ocorre (casa, escola, outros) e o que costuma desencadear', 'O que melhora e o que piora',
          'O que a família já tentou fazer e com que resultado', 'Impacto na vida da criança (sofrimento, escola, amizades, família)',
          'Como a criança/adolescente entende o motivo da consulta', { q: 'A criança/adolescente concorda em ser atendida?', op: ['Sim', 'Com resistência', 'Não'], t: 1 },
          'Expectativas da família com o processo terapêutico', 'Pontos fortes, interesses e o que a criança faz bem (a partir da percepção da família)'] },
        { t: '4. Histórico de saúde geral e mental', itens: [
          { q: 'Gestação', op: ['Planejada', 'Não planejada'], t: 1, h: 'Aceitação, pré-natal, intercorrências, uso de medicamentos/substâncias, estresse materno' },
          { q: 'Parto', op: ['Normal', 'Cesárea', 'A termo', 'Prematuro'], m: 1, t: 1, h: 'Idade gestacional (semanas) e observações' },
          'Peso/comprimento ao nascer, Apgar, complicações neonatais (UTI, icterícia, hipóxia)', 'Amamentação e vínculo inicial com os cuidadores',
          'Doenças, alergias ou síndromes diagnosticadas', 'Internações, cirurgias, traumatismos cranianos, convulsões, desmaios',
          'Visão e audição (última avaliação, uso de óculos ou aparelho)', 'Medicações em uso (nome, dose, horário, prescritor)',
          { q: 'Acompanhamentos atuais', op: ['Pediatra', 'Psiquiatra', 'Neurologista', 'Fonoaudiólogo', 'Terapeuta ocupacional', 'Psicopedagogo', 'Outros'], m: 1, t: 1 },
          'Tratamentos psicológicos ou psiquiátricos anteriores (motivo, duração, motivo do término)',
          { q: 'Sono', op: ['Dificuldade para iniciar', 'Despertares', 'Pesadelos', 'Terror noturno', 'Sonambulismo', 'Divide cama/quarto'], m: 1, t: 1, h: 'Horário de dormir e acordar' },
          { q: 'Alimentação', op: ['Seletividade', 'Compulsão', 'Restrição', 'Preocupação com peso/corpo', 'Sem alterações'], m: 1, t: 1 },
          'Histórico familiar de saúde mental e neurodesenvolvimento (depressão, ansiedade, TDAH, TEA, bipolaridade, psicose, dependência química, suicídio) e quem na família',
          'Histórico familiar de doenças clínicas relevantes'] },
        { t: '5. Desenvolvimento neuropsicomotor, emocional e comportamental', itens: [
          'Marcos motores: sustentou a cabeça, sentou, engatinhou, andou (idade em meses)', 'Coordenação motora fina e grossa (desenho, escrita, esportes, quedas frequentes)',
          'Linguagem: balbucio, primeiras palavras, frases (idade); trocas na fala, gagueira, atraso',
          'Comunicação e interação: contato visual, resposta ao nome, brincar simbólico, compreensão de ordens',
          'Interesses restritos, rotinas rígidas, movimentos repetitivos, sensibilidade a sons, texturas ou luz',
          'Controle esfincteriano: desfralde diurno e noturno (idade); enurese ou encoprese atual',
          'Autonomia para a idade: vestir-se, higiene, alimentar-se, organizar pertences, tarefas domésticas',
          'Atenção e atividade: dificuldade para manter o foco, agitação, impulsividade, esquecimentos',
          { q: 'Humor e emoções', op: ['Tristeza persistente', 'Irritabilidade', 'Medos ou fobias', 'Preocupação excessiva', 'Choro fácil', 'Apatia', 'Desânimo'], m: 1, t: 1 },
          { q: 'Reação à frustração, a limites e a mudanças de rotina', op: ['Birras intensas', 'Agressividade física ou verbal', 'Isolamento', 'Oposição', 'Autoagressão'], m: 1, t: 1 },
          'Comportamentos específicos: mentir, furtar, destruir objetos, crueldade com animais, fugas, tiques, roer unhas, manias',
          'Brincadeiras e atividades preferidas; presença de amigos imaginários', 'Temperamento descrito pela família (do bebê à fase atual)',
          { q: 'Puberdade e sexualidade (a partir de 9 a 10 anos)', h: 'Sinais de puberdade/menarca (idade), como o tema é tratado em casa, dúvidas, namoro, orientação sexual e identidade de gênero, comportamentos de risco', min: 9 }] },
        { t: '6. Histórico educacional e aprendizagem', itens: [
          { q: 'Escola atual, série/ano e turno', op: ['Manhã', 'Tarde', 'Integral'], t: 1 }, { q: 'Rede', op: ['Pública', 'Privada', 'Domiciliar'] },
          'Entrada na educação infantil: idade e adaptação à separação dos pais', { q: 'Desempenho atual', op: ['Excelente', 'Bom', 'Regular', 'Com dificuldades'] },
          { q: 'Dificuldades específicas', op: ['Leitura', 'Escrita', 'Matemática', 'Atenção', 'Memória', 'Organização das tarefas'], m: 1, t: 1 },
          'Idade de alfabetização e ritmo em relação à turma', 'Comportamento em sala e no recreio; queixas de professores ou coordenação',
          'Relação com professores e colegas; frequência e faltas; recusa escolar', 'Adaptação curricular, mediador, sala de recursos ou AEE; laudo entregue à escola',
          'Reprovações, mudanças de escola, suspensões', 'Rotina de estudo em casa e quem acompanha as tarefas', { q: 'Aspirações escolares e profissionais (adolescentes)', min: 12 },
          'Avaliações anteriores (psicopedagógica, neuropsicológica) e relatórios disponíveis'] },
        { t: '7. Contexto social, familiar, rotina e fatores de risco e proteção', itens: [
          'Relação com pai, mãe, irmãos e outros cuidadores', 'Regras, limites e consequências em casa; consenso entre os cuidadores',
          'Estilo de comunicação e demonstrações de afeto na família',
          { q: 'Eventos estressores', op: ['Separação dos pais', 'Luto', 'Mudança de casa/cidade', 'Nascimento de irmão', 'Doença na família', 'Perda de emprego', 'Conflitos graves'], m: 1, t: 1 },
          { q: 'Amizades: faz e mantém com facilidade?', op: ['Sim', 'Não', 'Prefere mais novos', 'Prefere mais velhos'], m: 1, t: 1 },
          'Bullying ou cyberbullying (sofrido ou praticado)', 'Atividades extracurriculares, esportes, artes, idiomas, vida religiosa ou comunitária',
          'Rotina diária (acordar, escola, refeições, lazer, tarefas, dormir) e tempo com cada cuidador',
          'Telas e internet: tempo médio diário, conteúdos, redes sociais, jogos online, supervisão',
          { q: 'Uso ou experimentação de álcool, tabaco, vape ou outras substâncias (a partir de 10 a 12 anos)', min: 10, risco: 1 },
          { q: 'Exposição a violência, negligência, abuso ou conflito intenso em casa ou fora dela', risco: 1 },
          { q: 'Ideação suicida, comportamento autolesivo, fugas de casa (perguntar diretamente, a partir dos 10 anos)', min: 10, risco: 1 },
          { q: 'Acesso a meios letais em casa (armas, medicamentos); medidas de segurança já adotadas', risco: 1 },
          'Fatores de proteção: vínculos seguros, adulto de confiança, hobbies, religiosidade, rede de amigos',
          { q: 'Necessidade de notificação ou articulação com rede de proteção (Conselho Tutelar, CRAS/CREAS, escola)', risco: 1 }] },
        { t: '8. Observações clínicas e impressões iniciais do profissional', itens: [
          'Aparência, comportamento e interação da criança/adolescente durante a entrevista',
          'Postura dos responsáveis, coerência e consistência do relato, vínculo com a criança', 'Fatores de risco identificados e conduta imediata, se houver',
          'Hipóteses iniciais e necessidade de diagnóstico diferencial', 'Plano de avaliação (instrumentos, sessões com a criança, devolutiva, contato com a escola)',
          'Encaminhamentos (psiquiatria, neurologia, fonoaudiologia, outros)', 'Acordos do contrato terapêutico: frequência, valor, faltas, sigilo e seus limites'] }
      ]
    }
  };
  // ids estáveis: modelo-seção-item
  for (const [mk, f] of Object.entries(FICHAS)) f.secoes.forEach((s, si) => { s.itens = s.itens.map((it, ii) => Object.assign(typeof it === 'string' ? { q: it } : it, { id: `${mk[0]}${si}_${ii}` })); });
  // múltipla escolha em todas as perguntas possíveis, sempre com campo de observação (anamnese-opcoes.js)
  if (typeof window.aplicarOpcoesAnamnese === 'function') window.aplicarOpcoesAnamnese(FICHAS);
  for (const f of Object.values(FICHAS)) f.secoes.forEach(s => s.itens.forEach(it => { if (it.op) it.t = 1; }));
  window.FICHAS_ANAMNESE = FICHAS;

  const modeloPorIdade = n => n === null || n === undefined || n === '' || isNaN(n) ? null : (+n >= 18 ? 'adulto' : 'infanto');
  const idadeAnam = p => { const a = p.anamnese || {}; if (a.idade !== undefined && a.idade !== '' && a.idade !== null) return +a.idade; const n = age(p.ident.nascimento); return n === null ? null : n; };
  const vazio = v => v === undefined || v === null || (Array.isArray(v) ? !v.length : !String(v).trim());
  window.anamneseResumo = function (p) {
    const a = p.anamnese; if (!a || !a.modelo || !a.resp || !a.resp[a.modelo]) return null;
    const f = FICHAS[a.modelo], r = a.resp[a.modelo]; let tot = 0, feitas = 0;
    f.secoes.forEach(s => s.itens.forEach(it => { tot++; if (!vazio(r[it.id]) || !vazio(r[it.id + '_t'])) feitas++; }));
    return { modelo: a.modelo, nome: f.nome, titulo: f.titulo, tot, feitas, em: a.atualizadoEm };
  };
  function preenchimento(p, it) {
    const i = p.ident, n = age(i.nascimento), r1 = (i.responsaveis || [])[0] || {};
    switch (it.pf) {
      case 'hoje': return today();
      case 'nome': return i.nome || '';
      case 'nascimento': return i.nascimento ? fmtD(i.nascimento) : '';
      case 'idade': { const k = idadeAnam(p); return k !== null ? k + ' anos' : ''; }
      case 'nascidade': return i.nascimento ? fmtD(i.nascimento) + (n !== null ? ` (${n} anos)` : '') : '';
      case 'endereco': return [i.endereco, i.cep].filter(Boolean).join(' · ');
      case 'cidade': return [i.cidade, i.uf].filter(Boolean).join('/');
      case 'telefone': return i.telefone || '';
      case 'email': return i.email || '';
      case 'profissao': return i.profissao || '';
      case 'contato': return [[i.endereco, i.cidade, i.uf].filter(Boolean).join(', '), i.telefone, i.email].filter(Boolean).join(' · ');
      case 'resp1': return r1.nome || '';
      case 'resp1c': return [r1.telefone, r1.email].filter(Boolean).join(' · ');
    }
    return '';
  }
  // respostas antigas em texto livre numa pergunta que agora tem opções vão para o campo de observação
  function migra(p) {
    const R = p.anamnese.resp;
    Object.keys(R).forEach(m => { const f = FICHAS[m]; if (!f) return; f.secoes.forEach(s => s.itens.forEach(it => {
      const v = R[m][it.id]; if (!it.op || v === undefined || Array.isArray(v) || v === '') return;
      if (!it.op.includes(v)) { R[m][it.id + '_t'] = [R[m][it.id + '_t'], v].filter(Boolean).join(' — '); R[m][it.id] = it.m ? [] : ''; }
    })); });
  }
  function garante(p, modelo) {
    p.anamnese = p.anamnese || { modelo: null, resp: {} };
    p.anamnese.resp = p.anamnese.resp || {};
    if (!p.anamnese._v2) { migra(p); p.anamnese._v2 = 1; }
    // a pergunta "Termo de consentimento" da seção 8 virou o quadro do termo no fim da ficha
    const ri = p.anamnese.resp.infanto; if (ri && ri.i7_7 && !(p.anamnese.termo && p.anamnese.termo.resp)) { p.anamnese.termo = Object.assign({}, p.anamnese.termo, { resp: ri.i7_7 }); delete ri.i7_7; }
    if (modelo && !p.anamnese.resp[modelo]) {
      const r = p.anamnese.resp[modelo] = {};
      FICHAS[modelo].secoes.forEach(s => s.itens.forEach(it => { if (it.pf) { const v = preenchimento(p, it); if (v) r[it.id] = v; } }));
    }
    return p.anamnese;
  }

  let tSave = null;
  const salvarJa = () => { clearTimeout(tSave); const p = P(); if (p && p.anamnese) p.anamnese.atualizadoEm = nowISO(); save(); atualizaContagem(); };
  const salvarDepois = () => { clearTimeout(tSave); tSave = setTimeout(salvarJa, 700); };
  function atualizaContagem() {
    const p = P(); const r = p && anamneseResumo(p); if (!r) return;
    const el = document.getElementById('anProg'); if (el) { el.querySelector('b').textContent = `${r.feitas} de ${r.tot}`; el.querySelector('i').style.width = Math.round(r.feitas / r.tot * 100) + '%'; }
    const f = FICHAS[r.modelo], resp = p.anamnese.resp[r.modelo];
    f.secoes.forEach((s, si) => { const c = document.getElementById('anSc' + si); if (c) { const n = s.itens.filter(it => !vazio(resp[it.id]) || !vazio(resp[it.id + '_t'])).length; c.textContent = `${n}/${s.itens.length}`; c.classList.toggle('ok', n === s.itens.length); } });
  }
  window.anTexto = function (el) { const p = P(); if (!p) return; const m = p.anamnese.modelo; p.anamnese.resp[m][el.dataset.a] = el.value; autoAltura(el); salvarDepois(); };
  window.anOpcao = function (el) {
    const p = P(); if (!p) return; const m = p.anamnese.modelo, id = el.dataset.a, multi = el.dataset.m === '1', v = el.dataset.v, r = p.anamnese.resp[m];
    let cur = r[id]; if (multi) { cur = Array.isArray(cur) ? cur : []; cur = cur.includes(v) ? cur.filter(x => x !== v) : cur.concat(v); }
    else cur = cur === v ? '' : v;
    r[id] = cur;
    el.parentElement.querySelectorAll('button').forEach(b => b.classList.toggle('on', multi ? cur.includes(b.dataset.v) : cur === b.dataset.v));
    salvarJa();
  };
  window.anIdade = function (el) {
    const p = P(); if (!p) return; garante(p);
    p.anamnese.idade = el.value === '' ? '' : Math.max(0, Math.min(120, parseInt(el.value, 10) || 0));
    const novo = modeloPorIdade(idadeAnam(p));
    if (novo !== p.anamnese.modelo) { if (novo) garante(p, novo); p.anamnese.modelo = novo; }
    // mantém o campo "Idade" da ficha de adultos igual à idade digitada (se ainda não foi editado à mão)
    if (p.anamnese.modelo === 'adulto' && p.anamnese.resp.adulto) { const k = idadeAnam(p), r = p.anamnese.resp.adulto, v = r.a1_3; if (k !== null && (!v || /^\d+ anos$/.test(v))) { r.a1_3 = k + ' anos'; const t = document.querySelector('[data-a="a1_3"]'); if (t) t.value = r.a1_3; } }
    if (novo !== (document.getElementById('anForm') ? document.getElementById('anForm').dataset.m : null)) { save(); paneAnamnese(p, true); }
    else salvarDepois();
  };
  window.anTodas = function (abrir) { document.querySelectorAll('#anForm details').forEach(d => { d.open = abrir; }); };
  function autoAltura(el) { el.style.height = 'auto'; el.style.height = Math.min(420, el.scrollHeight + 2) + 'px'; }

  window.paneAnamnese = function (p, manterFoco) {
    const n = idadeAnam(p);
    const auto = modeloPorIdade(n);
    garante(p);
    if (auto && p.anamnese.modelo !== auto) { garante(p, auto); p.anamnese.modelo = auto; }
    const a = p.anamnese, m = a.modelo, f = m && FICHAS[m];
    const idadeVal = a.idade !== undefined && a.idade !== '' && a.idade !== null ? a.idade : (age(p.ident.nascimento) ?? '');
    const daCad = (a.idade === undefined || a.idade === '' || a.idade === null) && age(p.ident.nascimento) !== null;
    const topo = `<div class="card an-topo"><div class="grid">
        <div class="c3"><label>Idade do paciente</label><div class="an-idade"><input id="anIdade" type="number" min="0" max="120" inputmode="numeric" value="${esc(idadeVal)}" oninput="anIdade(this)" placeholder="ex.: 34"><span>anos</span></div>
          <small class="meta">${daCad ? 'Calculada pela data de nascimento do cadastro.' : 'Digite a idade para abrir a ficha certa.'}</small></div>
        <div class="c9"><label>Ficha de anamnese</label>
          ${f ? `<div class="an-ficha"><b>${esc(f.titulo)}</b><small>${esc(f.sub)}</small></div>` : `<div class="an-ficha vazio">Digite a idade: <b>3 a 17 anos</b> abre a ficha Infantojuvenil e <b>18 anos ou mais</b> abre a ficha de Adultos.</div>`}</div></div>
      ${f && n !== null && +n < 3 ? `<div class="note warn" style="margin-top:10px">A ficha infantojuvenil foi elaborada para 3 a 17 anos. Para crianças menores, use as perguntas que se aplicarem.</div>` : ''}
      ${f ? `<div class="an-prog" id="anProg"><span>Respondidas: <b>0 de 0</b></span><div><i></i></div></div>` : ''}</div>`;
    if (!f) { pane(topo); return; }
    const r = a.resp[m], idadeNum = n === null ? null : +n;
    const item = it => {
      const v = r[it.id], t = r[it.id + '_t'];
      const fora = it.min && idadeNum !== null && idadeNum < it.min;
      const ops = it.op ? `<div class="an-ops">${it.op.map(o => `<button type="button" data-a="${it.id}" data-v="${esc(o)}" data-m="${it.m ? 1 : 0}" class="${(it.m ? Array.isArray(v) && v.includes(o) : v === o) ? 'on' : ''}" onclick="anOpcao(this)">${esc(o)}</button>`).join('')}</div>` : '';
      const campo = it.tipo === 'date'
        ? `<input type="date" data-a="${it.id}" value="${esc(v || '')}" onchange="anTexto(this)">`
        : (!it.op || it.t) ? `<textarea rows="1" data-a="${it.id + (it.op ? '_t' : '')}" placeholder="${esc(it.h || (it.op ? 'Observação (opcional)' : 'Resposta'))}" class="${it.op ? 'an-obs' : ''}" oninput="anTexto(this)">${esc(it.op ? (t || '') : (v || ''))}</textarea>` : '';
      return `<div class="an-item ${it.risco ? 'risco' : ''} ${fora ? 'fora' : ''}"><label>${esc(it.q)}${it.m ? ' <span class="an-varias">pode marcar mais de uma</span>' : ''}${fora ? ` <span class="tag">a partir de ${it.min} anos</span>` : ''}</label>${it.h && !it.op && !it.t ? `<small class="meta">${esc(it.h)}</small>` : ''}${ops}${campo}</div>`;
    };
    pane(topo + `<div class="an-barra"><button onclick="anTodas(true)">Abrir todas</button><button onclick="anTodas(false)">Fechar todas</button><span class="meta">Salva sozinho enquanto você digita.</span><button class="pri" onclick="anPDF()">${IC.printer || ''}<span>Gerar PDF</span></button></div>
      <div id="anForm" data-m="${m}">${f.secoes.map((s, si) => `<details class="card an-sec ${s.risco ? 'risco' : ''}" ${si === 0 || (S.anAberta || []).includes(m + si) ? 'open' : ''} ontoggle="anMarca('${m + si}',this.open)">
        <summary><b>${esc(s.t)}</b><span class="an-sc" id="anSc${si}">0/${s.itens.length}</span></summary>
        ${s.nota ? `<div class="note ${s.risco ? 'warn' : ''}">${esc(s.nota)}</div>` : ''}${s.itens.map(item).join('')}</details>`).join('')}</div>
      ${m === 'infanto' ? termoCard(p) : ''}
      <div class="note">A anamnese fica dentro do prontuário, criptografada como todo o resto, e entra no <b>Prontuário completo</b>. As respostas da outra ficha (se a idade mudar) não são apagadas.</div>`);
    document.querySelectorAll('#anForm textarea').forEach(autoAltura);
    atualizaContagem();
    if (manterFoco) { const i = document.getElementById('anIdade'); if (i) { i.focus(); const l = i.value.length; try { i.setSelectionRange(l, l); } catch (e) {} } }
  };
  window.anMarca = function (k, aberto) { S.anAberta = (S.anAberta || []).filter(x => x !== k); if (aberto) S.anAberta.push(k); };

  // texto da ficha (para o prontuário completo e para o PDF)
  function linhas(p, todas) {
    const a = p.anamnese, f = FICHAS[a.modelo], r = a.resp[a.modelo], out = [];
    f.secoes.forEach(s => {
      const itens = s.itens.map(it => {
        const v = r[it.id], t = r[it.id + '_t'];
        const val = [Array.isArray(v) ? v.join(', ') : (it.tipo === 'date' && v ? fmtD(v) : v), t].filter(x => !vazio(x)).join(' — ');
        return (val || todas) ? [it.q, val || '', it] : null;
      }).filter(Boolean);
      if (itens.length) out.push({ t: s.t, itens });
    });
    return out;
  }
  window.anamneseHTML = function (p) {
    const r = anamneseResumo(p); if (!r || !r.feitas) return '';
    const tm = p.anamnese.termo || {}, termoL = r.modelo === 'infanto' && (tm.resp || tm.assent) ? `<p style="margin:10px 0 4px"><b>Termo de consentimento e assentimento</b></p><table><tr><td>Termo dos responsáveis</td><td>${esc(tm.resp || '—')}</td></tr><tr><td>Assentimento da criança/adolescente</td><td>${esc(tm.assent || '—')}</td></tr><tr><td>Data da assinatura</td><td>${tm.em ? fmtD(tm.em) : '—'}</td></tr></table>` : '';
    return `<h4>Anamnese — ${esc(r.titulo)}</h4>${termoL}${linhas(p).map(s => `<p style="margin:10px 0 4px"><b>${esc(s.t)}</b></p><table>${s.itens.map(([q, v]) => `<tr><td>${esc(q)}</td><td>${esc(v)}</td></tr>`).join('')}</table>`).join('')}`;
  };
  window.anPDF = function () {
    const p = P(); if (!p) return;
    modal(`<h2>PDF da anamnese</h2><p>Escolha o que vai no PDF.</p>
      <label class="chk"><input type="radio" name="anPdfM" value="r" checked> Só as perguntas respondidas</label>
      <label class="chk"><input type="radio" name="anPdfM" value="t"> Todas as perguntas (as sem resposta ficam em branco, para completar à mão)</label>
      <p class="meta">O PDF sai do Appsico sem criptografia. Guarde e envie apenas por canal seguro.</p>
      <div class="row-actions"><button onclick="closeModal()">Cancelar</button><button class="pri" id="anPdfGo">Gerar PDF</button></div>`);
    $('anPdfGo').onclick = async () => {
      const todas = (document.querySelector('input[name=anPdfM]:checked') || {}).value === 't'; closeModal();
      const f = FICHAS[p.anamnese.modelo], secs = linhas(p, todas);
      const txt = [`Paciente: ${p.ident.nome || '—'}${idadeAnam(p) !== null ? ` · ${idadeAnam(p)} anos` : ''}`, `Profissional: ${DB.prof.nome || ''} · CRP ${DB.prof.crp || ''}`];
      secs.forEach(s => { txt.push('## ' + s.t.toUpperCase()); s.itens.forEach(([q, v, it]) => txt.push(`${q}${/[?:]$/.test(q) ? '' : ':'} ${v || (it && it.op ? it.op.map(o => '( ) ' + o).join('  ') + '  Obs.: ________' : '______________________________')}`)); });
      try {
        const blob = buildPDF({ kind: 'anamnese', prof: DB.prof, titulo: f.titulo.replace(/^Ficha de /, '').toUpperCase().replace('—', '-'), texto: txt.join('\n'), cidade: DB.prof.cidade || '', data: today() });
        await deliverPDF(blob, `Anamnese - ${(p.ident.nome || 'paciente').replace(/[^\wÀ-ÿ ]+/g, '')}.pdf`);
      } catch (e) { toast('Não foi possível gerar o PDF: ' + e.message); }
    };
  };

  // ---------- Termo de consentimento dos responsáveis e assentimento da criança/adolescente ----------
  const respDe = p => (p.ident.responsaveis || []).filter(r => r && r.nome);
  function termoTexto(p) {
    const i = p.ident, pr = DB.prof, rs = respDe(p), n = idadeAnam(p);
    const nomeP = i.nome || '______________________________';
    const L = [];
    L.push('## 1. IDENTIFICAÇÃO');
    L.push(`Criança/adolescente: ${nomeP}${i.nascimento ? ` · nascimento ${fmtD(i.nascimento)}` : ''}${n !== null ? ` · ${n} anos` : ''}.`);
    if (rs.length) { rs.forEach((r, k) => L.push(`Responsável ${k + 1}: ${r.nome}${r.parentesco ? ` (${r.parentesco})` : ''}${r.cpf ? ` · CPF ${r.cpf}` : ' · CPF ____________________'}.`)); if (rs.length < 2) L.push('Responsável 2 (se houver): ________________________________________ · parentesco: ____________ · CPF ____________________.'); }
    else { L.push('Responsável 1: ________________________________________ · parentesco: ____________ · CPF ____________________.'); L.push('Responsável 2: ________________________________________ · parentesco: ____________ · CPF ____________________.'); }
    L.push(`Psicólogo(a) responsável: ${pr.nome || '____________________'} · CRP ${pr.crp || '__________'}.`);
    L.push('## 2. SOBRE O ATENDIMENTO');
    L.push(`Os responsáveis abaixo assinados autorizam a realização de avaliação e acompanhamento psicológico de ${nomeP}, conforme o artigo 8º do Código de Ética Profissional do Psicólogo (Resolução CFP nº 010/2005), que exige a autorização de ao menos um dos responsáveis para o atendimento de crianças e adolescentes.`);
    L.push('O atendimento tem por objetivo compreender as dificuldades apresentadas e oferecer cuidado psicológico adequado à idade, por meio de entrevistas com os responsáveis, sessões com a criança/adolescente (que podem incluir conversa, brincadeiras, desenhos, jogos e instrumentos psicológicos) e devolutivas periódicas.');
    L.push('Frequência, duração, valor das sessões, forma de pagamento e política de faltas e remarcações: conforme combinado no contrato terapêutico. Os responsáveis podem pedir esclarecimentos a qualquer momento e interromper o acompanhamento quando desejarem, de preferência com uma sessão de encerramento.');
    L.push('## 3. SIGILO E SEUS LIMITES');
    L.push('Tudo o que for dito e produzido nas sessões é sigiloso. Aos responsáveis serão comunicadas apenas as informações estritamente necessárias para promover medidas em benefício da criança/adolescente (artigo 13 do Código de Ética), preservando a confiança no vínculo terapêutico.');
    L.push('O sigilo poderá ser quebrado, na medida do estritamente necessário, quando houver risco à vida ou à integridade da criança/adolescente ou de terceiros, e nas situações previstas em lei. Suspeitas ou confirmações de violência, abuso ou negligência serão comunicadas ao Conselho Tutelar, conforme o Estatuto da Criança e do Adolescente (Lei nº 8.069/1990).');
    L.push('O contato com a escola, médicos ou outros profissionais só será feito com autorização dos responsáveis, exceto nas situações de proteção descritas acima.');
    L.push('## 4. REGISTROS E PROTEÇÃO DE DADOS');
    L.push('As informações do atendimento ficam registradas em prontuário psicológico, guardado com sigilo e criptografia pelo prazo mínimo de 5 (cinco) anos, conforme as normas do Conselho Federal de Psicologia. Os dados pessoais da criança/adolescente são tratados no seu melhor interesse e com o consentimento dos responsáveis, conforme o artigo 14 da Lei Geral de Proteção de Dados (Lei nº 13.709/2018).');
    L.push('## 5. DECLARAÇÃO DOS RESPONSÁVEIS');
    L.push(`Declaramos que lemos (ou nos foi lido) este termo, que recebemos explicações claras sobre o atendimento, o sigilo e seus limites, que tivemos a oportunidade de tirar dúvidas e que autorizamos, de forma livre e esclarecida, o atendimento psicológico de ${nomeP}.`);
    L.push('## 6. TERMO DE ASSENTIMENTO DA CRIANÇA/ADOLESCENTE');
    L.push(`Eu, ${i.nome ? i.nome.split(' ')[0] : '____________________'}, conversei com o(a) psicólogo(a) e entendi que vamos nos encontrar para conversar, brincar e pensar juntos sobre o que eu sinto e sobre o que está difícil para mim. Entendi que o que eu contar fica guardado entre nós, e que só será contado para outra pessoa se for preciso para me proteger. Entendi também que posso fazer perguntas e dizer quando não quiser falar sobre alguma coisa. Eu concordo em participar.`);
    L.push('Forma do assentimento: ( ) assinatura da criança/adolescente   ( ) nome escrito ou desenho   ( ) concordância verbal registrada pelo(a) psicólogo(a).');
    return L.join('\n');
  }
  function termoAssinaturas(p) {
    const rs = respDe(p), i = p.ident, a = [];
    (rs.length >= 2 ? rs.slice(0, 2) : rs.concat([{}, {}]).slice(0, 2)).forEach((r, k) => a.push({ nome: r.nome || '', papel: r.nome ? `Responsável ${k + 1}${r.parentesco ? ' (' + r.parentesco + ')' : ''} — responsável legal` : `Responsável ${k + 1}${k ? ' (se houver)' : ''} — nome e assinatura` }));
    a.push({ nome: i.nome || '', papel: 'Criança/adolescente (assentimento)' });
    return a;
  }
  window.anTermoPDF = async function () {
    const p = P(); if (!p) return;
    try {
      const blob = buildPDF({ kind: 'termo', prof: DB.prof, titulo: 'TERMO DE CONSENTIMENTO DOS RESPONSÁVEIS E ASSENTIMENTO DA CRIANÇA/ADOLESCENTE', texto: termoTexto(p), cidade: DB.prof.cidade || '', data: today(), assinaturas: termoAssinaturas(p) });
      await deliverPDF(blob, `Termo de consentimento - ${(p.ident.nome || 'paciente').replace(/[^\wÀ-ÿ ]+/g, '')}.pdf`);
    } catch (e) { toast('Não foi possível gerar o termo: ' + e.message); }
  };
  window.anTermoStatus = function (campo, v) {
    const p = P(); if (!p) return; garante(p); p.anamnese.termo = p.anamnese.termo || {};
    p.anamnese.termo[campo] = p.anamnese.termo[campo] === v ? '' : v;
    if (campo === 'resp' && p.anamnese.termo.resp === 'Assinado' && !p.anamnese.termo.em) p.anamnese.termo.em = today();
    save(); paneAnamnese(p);
    const c = document.getElementById('anTermo'); if (c) c.scrollIntoView({ block: 'center' });
  };
  window.anTermoData = function (el) { const p = P(); if (!p) return; garante(p); p.anamnese.termo = p.anamnese.termo || {}; p.anamnese.termo.em = el.value; save(); };
  function termoCard(p) {
    const t = (p.anamnese && p.anamnese.termo) || {}, rs = respDe(p);
    const bt = (campo, ops) => `<div class="an-ops">${ops.map(o => `<button type="button" class="${t[campo] === o ? 'on' : ''}" onclick="anTermoStatus('${campo}','${o}')">${esc(o)}</button>`).join('')}</div>`;
    return `<div class="card an-termo" id="anTermo"><h3>Termo de consentimento dos responsáveis e assentimento da criança/adolescente</h3>
      <p class="meta">Para ser assinado pelos pais ou responsável legal${rs.length ? ` (${rs.map(r => esc(r.nome)).join(' e ')})` : ''} e pela criança/adolescente, conforme o Código de Ética do Psicólogo (arts. 8º e 13), o ECA e a LGPD. O PDF já sai com os nomes do cadastro e as linhas de assinatura.</p>
      ${rs.length ? '' : '<div class="note warn">Nenhum responsável no cadastro: o termo sai com os campos em branco para preencher à mão. Para sair com os nomes, cadastre os responsáveis em <b>1. Cadastro</b>.</div>'}
      <details class="an-termo-txt"><summary>Ler o termo completo</summary><div>${termoTexto(p).split('\n').map(l => l.startsWith('## ') ? `<p><b>${esc(l.slice(3))}</b></p>` : `<p>${esc(l)}</p>`).join('')}</div></details>
      <button class="pri" onclick="anTermoPDF()">${IC.printer || ''}<span>Gerar termo para assinatura (PDF)</span></button>
      <div class="an-item"><label>Termo dos responsáveis</label>${bt('resp', ['Assinado', 'Pendente'])}</div>
      <div class="an-item"><label>Assentimento da criança/adolescente</label>${bt('assent', ['Assinado', 'Concordância verbal registrada', 'Pendente'])}</div>
      <div class="an-item"><label>Data da assinatura</label><input type="date" value="${esc(t.em || '')}" onchange="anTermoData(this)"></div></div>`;
  }
  window.anTermoCard = termoCard;
})();
