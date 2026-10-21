# Enigma x64 7.40: fluxo de unpacking no IDA

Este projeto reúne um **script IDAPython para IDA 9.4** e dois módulos auxiliares. Ele acompanha um executável PE x64 protegido pelo Enigma Protector 7.40 até o ponto de entrada original (OEP), salva um dump preparado e mostra os dados encontrados para continuar o reparo dos imports no Scylla.

O núcleo de análise foi verificado com duas amostras da versão 7.40; o fluxo completo no IDA foi exercitado em uma delas. Os endereços são obtidos do executável aberto e do processo em execução; não há base, OEP ou IAT fixos de uma amostra. Outras configurações do protetor podem exigir análise manual.

## Arquivos

| Arquivo | Função |
| --- | --- |
| `ida_enigma740_generic.py` | Script principal: controla o depurador, acompanha as paradas e gera o dump. |
| `ida_enigma740_api.py` | Resolve APIs das DLLs carregadas e trata as duas chamadas antidebug observadas. |
| `enigma740_generic_core.py` | Analisa o PE, procura a transferência ao OEP, infere a IAT e prepara o arquivo para o Scylla. |

Mantenha os três arquivos `.py` **na mesma pasta**. Execute somente `ida_enigma740_generic.py` pelo menu do IDA. Os outros dois são importados por ele.

## Requisitos

- Windows x64 e IDA 9.4 com IDAPython e depurador **Local Windows**.
- Um executável PE x64 protegido pelo Enigma Protector 7.40 para analisar.
- Scylla x64 para reconstruir os imports depois da captura.

O script usa a biblioteca padrão do Python e os módulos do IDA; não requer instalação de pacote `pip` nem símbolos PDB para localizar as APIs.

## Passo a passo

1. Abra o **executável protegido** no IDA e escolha o depurador **Local Windows**.
2. Acesse **File > Script file** e selecione `ida_enigma740_generic.py`. Se a depuração ainda não começou, o script inicia o processo. Se já começou, deixe o processo pausado no entry point protegido antes de executar o script.
3. Na janela **Output**, confirme a linha `[Enigma 7.40 generic] loading workflow`. Acompanhe as mensagens com esse prefixo. Se houver erro de importação, confira se os três `.py` estão juntos.
4. O script resolve `NtSetInformationThread` e observa chamadas da classe `0x11` (`ThreadHideFromDebugger`) feitas pelo módulo protegido. Também observa `CheckRemoteDebuggerPresent` se a amostra a chamar. Nessas chamadas específicas, simula um retorno que permite continuar a depuração. Ele usa breakpoints de execução e não altera as DLLs do Windows no disco.
5. O script procura na memória a sequência final observada na versão estudada, `48 8B 45 E0 48 8B 65 F8 FF E0` (`jmp rax` no final). Confirma que a mesma thread chegou ao destino executável antes de identificá-lo como OEP.
6. Ao chegar ao OEP, a janela **Salvar como** pede o caminho do dump `.exe`. Escolha um nome novo. O processo fica pausado no OEP.
7. No **Output**, copie os valores em hexadecimal da linha `SCYLLA`: `OEP`, `VA` da IAT e `Size`. A faixa da IAT só é impressa quando a inferência tem confiança alta; caso contrário, use a busca de IAT do Scylla.
8. Anexe o **Scylla x64** ao processo ainda pausado, confira a IAT, obtenha os imports, use **Autotrace** nas entradas redirecionadas pelo Enigma quando necessário e aplique **Fix Dump** ao `.exe` produzido pelo script. Valide o executável resultante fora do depurador.

O programa não precisa chamar `CheckRemoteDebuggerPresent` para o OEP ser encontrado. A presença dessa chamada depende da amostra e das opções do protetor.

## Arquivos gerados

O nome escolhido na janela **Salvar como** determina três arquivos na mesma pasta:

| Saída | Conteúdo |
| --- | --- |
| `nome.exe` | PE com layout preparado e entry point ajustado, ainda **pré-Scylla**. |
| `nome.mem.bin` | Imagem bruta capturada da memória, com offset igual ao RVA. |
| `nome.json` | Relatório com base carregada, OEP, análise de IAT, `.bss`, páginas ilegíveis e eventos. |

O script recusa sobrescrever qualquer um desses arquivos. O JSON registra o caminho do executável analisado e dos arquivos gerados; revise esse relatório antes de publicá-lo.

## Controles no console Python do IDA

Depois de executar o script, o objeto `enigma740_generic` fica disponível no console:

```python
enigma740_generic.status()       # Estado atual e último erro, se houver
enigma740_generic.probe_jump()   # Repetir busca do salto com o processo pausado
enigma740_generic.advance()      # Continuar uma parada reconhecida, se o modo automático estiver desligado
enigma740_generic.save()         # Reabrir Salvar como, se o processo ainda estiver no OEP
enigma740_generic.abort()        # Remover os breakpoints criados pelo script
```

Para examinar cada parada antes de continuar, altere `AUTO_CONTINUE = False` no início de `ida_enigma740_generic.py` antes de carregá-lo. Nesse modo, use `advance()` após a inspeção.

### Se o salto final não for detectado

Com o processo pausado, `probe_jump()` faz nova busca na imagem mapeada. Se a variante usar outro padrão, acompanhe manualmente o `jmp rax`: anote o endereço do salto, execute **uma instrução** para chegar ao destino e, com o IDA parado nele, use:

```python
enigma740_generic.confirm_manual_oep(endereco_do_jmp, endereco_do_destino)
```

O relatório marca essa confirmação como observação manual. O script valida a instrução de origem, o destino, `RIP` e `RAX` antes de aceitá-la.

### Se a seção `.bss` precisar de ajuste

O script tenta selecionar automaticamente uma seção original com `RawSize = 0` e a flag de dados não inicializados **somente quando existe uma candidata única**. Confira o campo `bss_source` no JSON e os cabeçalhos do PE produzido. Essa heurística não comprova que qualquer seção sem dados no arquivo protegido seja a `.bss` original.

Se precisar indicar o RVA inicial da seção, **cancele a janela Salvar como** ao chegar ao OEP e execute, por exemplo:

```python
enigma740_generic.set_bss_rva(0x290000)
enigma740_generic.save()
```

Substitua `0x290000` pelo RVA da seção da sua amostra. O script exige que seja uma seção original com `RawSize = 0` no arquivo protegido. Depois de **Fix Dump**, confira novamente os cabeçalhos: o Scylla pode regravá-los.

## Alcance e limites

- A assinatura da transferência final e uma pista relativa ao loader foram observadas em duas amostras. Uma configuração diferente pode não parar no OEP automaticamente. A pista isolada nunca confirma o OEP.
- O script não identifica formalmente o stub inicial do Enigma. Ele valida o PE x64 e a transferência observada durante a depuração.
- O tratamento antidebug cobre as chamadas observadas a `NtSetInformationThread` com classe `0x11` e `CheckRemoteDebuggerPresent` com pseudohandle do processo atual, feitas pelo módulo protegido. Outras técnicas exigem análise adicional. Se nomes de API distintos resolverem para endereços diferentes, somente a entrada primária é monitorada.
- A captura de imagem tem limite de **512 MiB**. Páginas ilegíveis da aplicação impedem o dump; páginas ilegíveis do loader são registradas no JSON.
- A faixa da IAT é uma inferência. O script **não reconstrói** descritores, nomes de APIs nem redirecionamentos do Enigma. O resultado `.exe` pode não abrir antes do reparo no Scylla e de outras correções de metadados.
- Depois do dump, o monitoramento das duas APIs continua ativo para observar verificações em tempo de execução. Use `abort()` para encerrar o fluxo e remover os breakpoints do script.

Este pacote é um **script executado por File > Script file**, não um plugin instalado no diretório `plugins` do IDA.
