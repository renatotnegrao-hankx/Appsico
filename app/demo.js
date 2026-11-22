/* Dados de demonstração do Appsico: 10 pacientes fictícios com o fluxo completo de atendimento.
 * Tudo o que é criado aqui fica marcado com demo:true e pode ser removido em Configurações. */
(function () {
  const pad = n => String(n).padStart(2, '0');
  const iso = d => d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate());
  const hoje = () => { const d = new Date(); d.setHours(12, 0, 0, 0); return d; };
  const somaDias = (d, k) => { const x = new Date(d); x.setDate(x.getDate() + k); return x; };
  const somaMinutos = (h, m) => { const [a, b] = h.split(':').map(Number), t = a * 60 + b + m; return pad(Math.floor(t / 60)) + ':' + pad(t % 60); };
  const nasc = anos => iso(somaDias(hoje(), -Math.round(anos * 365.25) - 40));
  let seq = 0; const id = () => 'demo' + Date.now().toString(36) + (seq++);
  function cpf(seed) {
    const n = []; let s = seed * 7919 + 12345;
    for (let i = 0; i < 9; i++) { s = (s * 1103515245 + 12345) % 2147483648; n.push(s % 10); }
    const dv = len => { let t = 0; for (let i = 0; i < len; i++) t += n[i] * (len + 1 - i); const r = (t * 10) % 11; return r === 10 ? 0 : r; };
    n.push(dv(9)); n.push(dv(10));
    return `${n.slice(0, 3).join('')}.${n.slice(3, 6).join('')}.${n.slice(6, 9).join('')}-${n.slice(9).join('')}`;
  }

  const PACIENTES = [
    { nome: 'Ana Beatriz Ramos', idade: 34, prof: 'Analista financeira', cidade: 'São Paulo', uf: 'SP', mod: 'Presencial', valor: 180, sem: 12, freq: 7, hora: '09:00', dow: 1,
      queixa: 'Preocupação excessiva e difícil de controlar com trabalho e saúde da família, tensão muscular, irritabilidade e dificuldade para dormir há cerca de 8 meses.',
      hist: 'Procurou atendimento por indicação do clínico geral após episódios de taquicardia sem causa orgânica. Relata aumento de cobranças no trabalho após promoção.',
      diag: [[2, 'Avaliação psicológica', '', 'Entrevista clínica semiestruturada, BAI', 'Escore no BAI compatível com ansiedade moderada. Preocupações persistentes em múltiplos domínios, com prejuízo no sono e na concentração.'],
             [3, 'Diagnóstico', 'F41.1', 'Entrevista clínica, BAI, critérios diagnósticos', 'Quadro compatível com Transtorno de Ansiedade Generalizada. Devolutiva realizada com a paciente.']],
      obj: [['Curto prazo', 'Reconhecer gatilhos e sinais iniciais de ansiedade.', 'Alcançado'], ['Médio prazo', 'Reduzir a ruminação noturna e melhorar a qualidade do sono.', 'Em andamento'], ['Longo prazo', 'Desenvolver estratégias de enfrentamento para demandas do trabalho.', 'Em andamento']],
      notas: ['Acolhimento e escuta da demanda. Paciente colaborativa, relata cansaço e preocupação constante.', 'Aplicação do BAI e investigação do histórico. Identificadas situações de trabalho como principais gatilhos.', 'Devolutiva da avaliação. Psicoeducação sobre ansiedade e ciclo da preocupação.', 'Treino de respiração diafragmática e registro de pensamentos. Boa adesão às tarefas.', 'Trabalhada a reestruturação de pensamentos catastróficos. Relata melhora no sono em alguns dias.', 'Revisão do registro semanal. Paciente conseguiu delegar tarefas no trabalho, com menos culpa.'] },
    { nome: 'Carlos Eduardo Nunes', idade: 45, prof: 'Gerente comercial', cidade: 'Campinas', uf: 'SP', mod: 'Presencial', valor: 200, sem: 9, freq: 7, hora: '18:00', dow: 2,
      queixa: 'Tristeza persistente, perda de interesse por atividades antes prazerosas, cansaço e isolamento social há aproximadamente 4 meses.',
      hist: 'Separação conjugal há um ano. Refere diminuição do rendimento no trabalho e afastamento dos amigos. Nega ideação suicida no momento da avaliação.',
      diag: [[2, 'Avaliação psicológica', '', 'Entrevista clínica, BDI-II', 'Escore no BDI-II compatível com sintomas depressivos moderados. Avaliado risco: sem ideação suicida atual, rede de apoio presente.'],
             [3, 'Diagnóstico', 'F32.1', 'Entrevista clínica, BDI-II', 'Quadro compatível com episódio depressivo moderado. Indicada avaliação psiquiátrica complementar.']],
      obj: [['Curto prazo', 'Retomar ao menos duas atividades prazerosas por semana.', 'Em andamento'], ['Médio prazo', 'Reorganizar a rotina de sono e alimentação.', 'Em andamento'], ['Longo prazo', 'Elaborar o processo de separação e fortalecer a rede social.', 'Em andamento']],
      enc: ['Psiquiatria — Dr(a). Fernando Alves (fictício)', 'Avaliação para possível tratamento medicamentoso', 'Iniciou acompanhamento psiquiátrico'],
      notas: ['Acolhimento. Paciente relata desânimo e dificuldade para sair de casa.', 'Aplicação do BDI-II e avaliação de risco. Combinado plano de segurança.', 'Devolutiva e encaminhamento para avaliação psiquiátrica. Paciente aceitou.', 'Ativação comportamental: lista de atividades prazerosas. Retomou caminhadas.', 'Relata início do acompanhamento psiquiátrico. Humor um pouco mais estável.', 'Trabalhados sentimentos ligados à separação. Choro durante a sessão, com boa elaboração.'] },
    { nome: 'Lucas Ferreira', idade: 9, prof: 'Estudante (4º ano)', cidade: 'Santos', uf: 'SP', mod: 'Presencial', valor: 160, sem: 10, freq: 7, hora: '14:00', dow: 3,
      resp: { nome: 'Juliana Ferreira', parentesco: 'Mãe', telefone: '13998762210', email: 'juliana.ferreira@exemplo.com' },
      queixa: 'Encaminhado pela escola por desatenção, agitação em sala e dificuldade para concluir tarefas. Mãe relata impulsividade em casa.',
      hist: 'Desenvolvimento neuropsicomotor dentro do esperado. Queixas escolares desde o 2º ano. Relatório da professora anexado aos documentos.',
      diag: [[3, 'Avaliação psicológica', '', 'Entrevista com responsável, observação lúdica, SNAP-IV (pais e professora)', 'Escores elevados em desatenção e hiperatividade/impulsividade, em mais de um contexto (casa e escola).'],
             [4, 'Hipótese diagnóstica', 'F90.0', 'SNAP-IV, entrevista, relatório escolar', 'Hipótese de TDAH apresentação combinada. Indicada avaliação neuropediátrica para confirmação.']],
      obj: [['Curto prazo', 'Orientar a família sobre rotina e combinados em casa.', 'Alcançado'], ['Médio prazo', 'Desenvolver estratégias de organização para as tarefas escolares.', 'Em andamento'], ['Longo prazo', 'Melhorar a autorregulação emocional diante de frustrações.', 'Em andamento']],
      enc: ['Neuropediatria — Dra. Paula Mendes (fictícia)', 'Avaliação neurológica e confirmação diagnóstica', ''],
      sessResp: true,
      notas: ['Entrevista inicial com a mãe: histórico, rotina e queixas escolares.', 'Primeiro contato com Lucas por meio de jogos. Criança comunicativa, se distrai com facilidade.', 'Observação lúdica e aplicação do SNAP-IV com a mãe. Solicitado SNAP-IV à escola.', 'Devolutiva para a mãe e encaminhamento à neuropediatria.', 'Jogos de regras para treino de espera e tolerância à frustração. Boa participação.', 'Sessão com a responsável: montagem de quadro de rotina visual para casa.'] },
    { nome: 'Mariana Costa', idade: 28, prof: 'Designer', cidade: 'Rio de Janeiro', uf: 'RJ', mod: 'On-line', valor: 170, sem: 8, freq: 7, hora: '19:30', dow: 4,
      queixa: 'Crises súbitas de medo intenso com falta de ar, tremores e sensação de morte iminente. Passou a evitar transporte público.',
      hist: 'Primeira crise há 6 meses no metrô. Três idas ao pronto-socorro com exames normais. Trabalha em home office desde então.',
      diag: [[2, 'Diagnóstico', 'F41.0', 'Entrevista clínica, inventário de sintomas de pânico', 'Ataques de pânico recorrentes e inesperados, com preocupação persistente com novas crises e evitação. Compatível com Transtorno de Pânico.']],
      obj: [['Curto prazo', 'Compreender a crise de pânico e reduzir o medo das sensações.', 'Alcançado'], ['Médio prazo', 'Exposição gradual ao transporte público.', 'Em andamento']],
      notas: ['Acolhimento on-line. Paciente descreve as crises e o medo de novas ocorrências.', 'Investigação diagnóstica e psicoeducação sobre o ciclo do pânico.', 'Exposição interoceptiva leve na sessão (respiração acelerada). Tolerou bem.', 'Montada hierarquia de exposição. Primeiro passo: ir até a estação de metrô.', 'Relata ter ido à estação acompanhada, sem crise. Ansiedade 6/10.', 'Fez um trajeto curto sozinha. Ansiedade 4/10. Muito motivada.'] },
    { nome: 'Roberto Almeida', idade: 52, prof: 'Professor', cidade: 'Belo Horizonte', uf: 'MG', mod: 'Presencial', valor: 180, sem: 14, freq: 14, hora: '10:00', dow: 5,
      queixa: 'Dificuldade em lidar com a morte da esposa há 7 meses. Tristeza intensa, culpa e dificuldade de retomar a rotina.',
      hist: 'Esposa faleceu após doença prolongada; foi o principal cuidador. Dois filhos adultos, que moram em outra cidade.',
      diag: [[2, 'Avaliação psicológica', 'Z63.4', 'Entrevista clínica, Inventário de Luto Complicado', 'Reação de luto com intensidade elevada, sem critérios para luto prolongado até o momento. Acompanhar evolução.']],
      obj: [['Curto prazo', 'Dar espaço para a expressão do luto e da culpa.', 'Alcançado'], ['Médio prazo', 'Retomar atividades de trabalho e convívio.', 'Em andamento'], ['Longo prazo', 'Ressignificar a relação com a esposa e construir novos projetos.', 'Em andamento']],
      notas: ['Acolhimento. Paciente fala da esposa e dos meses de cuidado.', 'Aplicação do inventário. Trabalhada a culpa por não ter percebido a doença antes.', 'Elaboração por meio de lembranças e fotografias trazidas pelo paciente.', 'Relata ter voltado a dar aulas em meio período. Dias difíceis na data do aniversário dela.', 'Planejamento de visita aos filhos. Expressa vontade de voltar ao coral.'] },
    { nome: 'Fernanda Lima Souza', idade: 31, prof: 'Enfermeira', cidade: 'Curitiba', uf: 'PR', mod: 'Híbrido', valor: 170, sem: 7, freq: 7, hora: '20:00', dow: 1,
      queixa: 'Exaustão física e emocional, distanciamento dos pacientes e sensação de ineficácia no trabalho em UTI.',
      hist: 'Plantões de 12 horas com frequentes dobras. Afastada por 15 dias pelo médico do trabalho. Relata dificuldade em se desligar do trabalho.',
      diag: [[2, 'Avaliação psicológica', 'Z73.0', 'Entrevista clínica, MBI (Maslach Burnout Inventory)', 'Escores elevados em exaustão emocional e despersonalização, com baixa realização profissional. Compatível com síndrome de burnout.']],
      obj: [['Curto prazo', 'Estabelecer limites para horas extras e descanso.', 'Em andamento'], ['Médio prazo', 'Recuperar o sentido do trabalho e atividades fora dele.', 'Em andamento']],
      notas: ['Acolhimento. Paciente chorosa, relata não aguentar mais os plantões.', 'Aplicação do MBI e mapeamento da rotina.', 'Devolutiva. Construção de plano de autocuidado e limites.', 'Relata ter recusado uma dobra pela primeira vez. Culpa, mas alívio.', 'Sessão on-line. Discutida possibilidade de mudança de setor.'] },
    { nome: 'Pedro Henrique Martins', idade: 15, prof: 'Estudante (1º ano do ensino médio)', cidade: 'Porto Alegre', uf: 'RS', mod: 'Presencial', valor: 160, sem: 8, freq: 7, hora: '16:00', dow: 2,
      resp: { nome: 'Marcos Martins', parentesco: 'Pai', telefone: '51997654321', email: 'marcos.martins@exemplo.com' },
      queixa: 'Medo intenso de falar em público e de ser avaliado pelos colegas. Faltou a apresentações e evita o intervalo na escola.',
      hist: 'Mudou de escola no início do ano. Sempre foi tímido, mas os sintomas se intensificaram. Bom desempenho escolar.',
      diag: [[2, 'Avaliação psicológica', '', 'Entrevista com adolescente e pai, LSAS-CA', 'Escore elevado de ansiedade social, com evitação significativa de situações de exposição.'],
             [3, 'Diagnóstico', 'F40.1', 'LSAS-CA, entrevista clínica', 'Quadro compatível com Fobia Social (Transtorno de Ansiedade Social).']],
      obj: [['Curto prazo', 'Identificar pensamentos automáticos em situações sociais.', 'Alcançado'], ['Médio prazo', 'Participar de uma apresentação em sala.', 'Em andamento']],
      notas: ['Entrevista com o pai e com o adolescente. Pedro fala pouco, mas colabora.', 'Aplicação da LSAS-CA. Pedro descreve medo de "travar" e ser zoado.', 'Devolutiva para Pedro e para o pai. Psicoeducação sobre ansiedade social.', 'Role-play de apresentação curta na sessão. Ansiedade alta, mas concluiu.', 'Relata ter conversado com dois colegas no intervalo. Orgulhoso.'] },
    { nome: 'Juliana Prado', idade: 39, prof: 'Advogada', cidade: 'Brasília', uf: 'DF', mod: 'On-line', valor: 200, sem: 11, freq: 7, hora: '08:00', dow: 3,
      queixa: 'Pensamentos intrusivos sobre contaminação e necessidade de lavar as mãos repetidamente, chegando a mais de duas horas por dia.',
      hist: 'Sintomas desde a adolescência, com piora nos últimos dois anos. Já fez uso de medicação prescrita por psiquiatra, que mantém.',
      diag: [[2, 'Avaliação psicológica', '', 'Entrevista clínica, Y-BOCS', 'Escore no Y-BOCS na faixa grave. Obsessões de contaminação e compulsões de limpeza, com insight preservado.'],
             [3, 'Diagnóstico', 'F42.2', 'Y-BOCS, entrevista clínica', 'Quadro compatível com Transtorno Obsessivo-Compulsivo, forma mista. Plano de exposição com prevenção de resposta.'],
             [8, 'Reavaliação', 'F42.2', 'Y-BOCS', 'Redução de 30% no escore do Y-BOCS em relação à avaliação inicial.']],
      obj: [['Curto prazo', 'Montar hierarquia de exposição.', 'Alcançado'], ['Médio prazo', 'Reduzir o tempo diário de rituais para menos de 30 minutos.', 'Em andamento']],
      notas: ['Acolhimento on-line. Paciente descreve rituais e o impacto na rotina.', 'Aplicação do Y-BOCS e mapeamento das situações temidas.', 'Devolutiva e explicação da exposição com prevenção de resposta.', 'Primeira exposição: tocar maçaneta sem lavar as mãos por 10 minutos.', 'Exposições diárias realizadas em casa. Ansiedade diminui mais rápido.', 'Reavaliação com Y-BOCS: melhora significativa. Paciente animada.'] },
    { nome: 'Gabriel Souza Rocha', idade: 26, prof: 'Motoboy', cidade: 'Recife', uf: 'PE', mod: 'Presencial', valor: 150, sem: 6, freq: 7, hora: '17:00', dow: 4,
      queixa: 'Pesadelos, lembranças intrusivas e sobressaltos após acidente de trânsito grave há 5 meses. Não consegue voltar a pilotar.',
      hist: 'Acidente com fratura de perna; amigo que estava na garupa ficou gravemente ferido. Afastado pelo INSS.',
      diag: [[2, 'Diagnóstico', 'F43.1', 'Entrevista clínica, PCL-5', 'Escore no PCL-5 acima do ponto de corte, com revivência, evitação, alterações de humor e hiperexcitação. Compatível com Transtorno de Estresse Pós-Traumático.']],
      obj: [['Curto prazo', 'Estabilização: técnicas de aterramento e regulação.', 'Alcançado'], ['Médio prazo', 'Processamento da memória traumática.', 'Em andamento']],
      notas: ['Acolhimento. Paciente relata o acidente com muita emoção.', 'Aplicação do PCL-5. Ensinadas técnicas de aterramento para os sobressaltos.', 'Relata pesadelos menos frequentes. Construída linha da vida.', 'Início do processamento do trauma. Sessão intensa, paciente saiu estável.'] },
    { nome: 'Helena Duarte', idade: 67, prof: 'Aposentada', cidade: 'Florianópolis', uf: 'SC', mod: 'Presencial', valor: 170, sem: 16, freq: 7, hora: '11:00', dow: 5, max: 10, alta: true,
      queixa: 'Dificuldade para iniciar e manter o sono há mais de um ano, com preocupação e cansaço durante o dia.',
      hist: 'Insônia iniciada após aposentadoria. Uso ocasional de indutor do sono por conta própria, já comunicado ao médico.',
      diag: [[2, 'Avaliação psicológica', '', 'Entrevista clínica, ISI (Índice de Gravidade de Insônia), diário do sono', 'Insônia moderada, com hábitos de sono inadequados e preocupação noturna.'],
             [3, 'Diagnóstico', 'F51.0', 'ISI, diário do sono', 'Quadro compatível com insônia não orgânica. Plano com terapia cognitivo-comportamental para insônia.'],
             [9, 'Reavaliação', '', 'ISI, diário do sono', 'Índice de insônia na faixa sem insônia clinicamente significativa. Metas alcançadas.']],
      obj: [['Curto prazo', 'Ajustar higiene do sono e horários.', 'Alcançado'], ['Médio prazo', 'Reduzir o tempo para adormecer para menos de 30 minutos.', 'Alcançado'], ['Longo prazo', 'Manter o sono regular sem uso de indutor.', 'Alcançado']],
      notas: ['Acolhimento. Paciente relata noites mal dormidas e cochilos à tarde.', 'Aplicação do ISI e início do diário do sono.', 'Devolutiva. Orientações de higiene do sono e controle de estímulos.', 'Restrição de tempo na cama combinada. Paciente motivada.', 'Diário mostra melhora na eficiência do sono.', 'Trabalhadas preocupações noturnas com a técnica do "tempo da preocupação".', 'Reavaliação com ISI: melhora expressiva. Preparação para a alta.', 'Sessão de encerramento. Revisão das estratégias e plano de manutenção.'] }
  ];

  window.carregarDemo = function () {
    if (DB.patients.some(p => p.demo)) return toast('Os dados de demonstração já foram carregados');
    const H = hoje(), ag = DB.agenda || (DB.agenda = []);
    PACIENTES.forEach((x, idx) => {
      const p = blankPatient();
      p.id = id(); p.demo = true;
      const ini = somaDias(H, -x.sem * 7);
      while (ini.getDay() !== x.dow) ini.setDate(ini.getDate() + 1);
      const iniS = iso(ini);
      p.criadoEm = new Date(somaDias(ini, -3).setHours(10, 12 + idx, 0, 0)).toISOString();
      Object.assign(p.ident, { nome: x.nome, nascimento: nasc(x.idade), cpf: x.idade >= 12 ? cpf(idx + 1) : '', profissao: x.prof, cidade: x.cidade, uf: x.uf,
        endereco: 'Rua Exemplo, ' + (100 + idx * 37), cep: '00000-000', telefone: x.resp ? '' : '119' + String(87650000 + idx * 1111).slice(0, 8),
        email: x.resp ? '' : x.nome.split(' ')[0].toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '') + '@exemplo.com', valorSessao: x.valor.toFixed(2).replace('.', ',') });
      if (x.resp) p.ident.responsaveis = [Object.assign({ cpf: cpf(idx + 50) }, x.resp)];
      Object.assign(p.demanda, { queixa: x.queixa, historico: x.hist, dataInicio: iniS, modalidade: x.mod });
      // sessões
      const datas = []; for (let d = new Date(ini); d < H && datas.length < (x.max || 99); d = somaDias(d, x.freq)) datas.push(iso(d));
      datas.forEach((d, i) => {
        const tipo = x.sessResp && (i === 0 || i % 5 === 0) ? 'Sessão com responsável' : i === 2 && x.diag.length > 1 ? 'Devolutiva' : i === 1 ? 'Avaliação' : 'Sessão individual';
        const falta = !x.alta && i === datas.length - 4 && idx % 3 === 0;
        const texto = falta ? 'Paciente avisou com antecedência que não poderia comparecer.' : x.notas[i % x.notas.length];
        const pend = !falta && i >= datas.length - (idx % 4 === 1 ? 2 : idx % 4 === 2 ? 1 : 0);
        const e = { id: id(), data: d, hora: x.hora, horaFim: somaMinutos(x.hora, 50), num: String(i + 1), tipo: falta ? 'Falta justificada' : tipo, modalidade: x.mod === 'Híbrido' ? (i % 2 ? 'On-line' : 'Presencial') : x.mod,
          texto, intervencoes: falta ? '' : ['Escuta qualificada', 'Psicoeducação', 'Reestruturação cognitiva', 'Técnicas de exposição', 'Tarefa de casa revisada'][i % 5], intercorrencias: '',
          criadoEm: new Date(d + 'T' + somaMinutos(x.hora, 55) + ':00').toISOString(), retificacoes: [], valor: falta ? 0 : x.valor, pago: !falta && !pend, forma: !falta && !pend ? (i % 3 ? 'Pix' : 'Cartão de crédito') : '', pagoEm: !falta && !pend ? d : '' };
        p.evolucao.push(e);
        ag.push({ id: id(), demo: true, pid: p.id, data: d, hora: x.hora, dur: 50, status: falta ? 'faltou' : 'realizado', obs: '' });
      });
      // avaliação e diagnóstico
      p.diagnosticos = x.diag.map(([si, tipo, cid, ins, txt]) => { const d = datas[Math.min(si - 1, datas.length - 1)]; return { id: id(), data: d, tipo, cid, instrumentos: ins, texto: txt, criadoEm: new Date(d + 'T' + somaMinutos(x.hora, 58) + ':00').toISOString(), retificacoes: [] }; });
      // plano terapêutico
      const dObj = datas[Math.min(3, datas.length - 1)];
      p.objetivos = x.obj.map(([prazo, texto, status]) => ({ id: id(), prazo, data: dObj, pactuado: true, texto, status }));
      // encaminhamento
      if (x.enc) p.encaminhamentos.push({ id: id(), data: datas[Math.min(3, datas.length - 1)], destinatario: x.enc[0], finalidade: x.enc[1], retorno: x.enc[2] });
      // alta
      if (x.alta) { p.status = 'encerrado'; p.encerramento = { data: datas[datas.length - 1], motivo: 'Alta', descricao: 'Objetivos terapêuticos alcançados. Paciente orientada sobre manutenção dos ganhos e possibilidade de retorno.' }; }
      else {
        // próximas consultas
        for (let k = 0; k < 3; k++) {
          let d = new Date(datas[datas.length - 1] + 'T12:00'); d = somaDias(d, x.freq * (k + 1));
          if (d <= H && k === 0) d = somaDias(H, 1 + (idx % 3));
          ag.push({ id: id(), demo: true, pid: p.id, data: iso(d), hora: x.hora, dur: 50, status: k === 0 && idx % 2 ? 'confirmado' : 'agendado', obs: '' });
        }
      }
      DB.patients.push(p);
    });
    // algumas despesas do consultório
    const cs = DB.contas || (DB.contas = []), m = iso(H).slice(0, 8);
    [['Aluguel da sala', 'Aluguel / sala', 1200, '05', true], ['Supervisão clínica', 'Supervisão', 350, '10', true], ['Internet e telefone', 'Energia / internet', 150, '15', true], ['Anuidade CRP (parcela)', 'Conselho (CRP)', 98, '28', false]]
      .forEach(([desc, cat, valor, dia, pago]) => cs.push({ id: id(), demo: true, tipo: 'pagar', desc, cat, valor, venc: m + dia, pago: pago && m + dia <= iso(H), pagoEm: pago && m + dia <= iso(H) ? m + dia : '' }));
    save(); toast('10 pacientes de demonstração carregados'); go('home', { cur: null, flt: 'todos' });
  };
  window.removerDemo = function () {
    confirmBox('Remover dados de demonstração?', 'Os 10 pacientes fictícios, suas consultas e as despesas de exemplo serão apagados. Seus pacientes reais não são afetados.', 'Remover', () => {
      const ids = new Set(DB.patients.filter(p => p.demo).map(p => p.id));
      DB.patients = DB.patients.filter(p => !p.demo);
      DB.agenda = (DB.agenda || []).filter(a => !a.demo && !ids.has(a.pid));
      DB.contas = (DB.contas || []).filter(c => !c.demo);
      save(); toast('Dados de demonstração removidos'); render();
    });
  };
})();
