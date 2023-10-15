# Todo list api em Java com autenticação

Esse projeto é uma aplicação  de api  para a ferramenta Todo, onde é feito o cadastro do usuario e suas tarefas via api.

## 🚀 Começando

Faça  git clone  https://github.com/tsilva19/todolistjava.git

### 📋 Pré-requisitos

De que coisas você precisa para instalar o software e como instalá-lo?

```
maven
JAVA SDK 17
INSONMIA(Consumo da api)
```

### 🔧 Rodar o Projeto e como Funciona a autenticação

Uma série de exemplos passo-a-passo que informam o que você deve executar para ter um ambiente de desenvolvimento em execução.

Rodar a aplicação via terminal:

```
mvn springboot:run
```

#### Como funciona a autenticação

Existe um arquivo de codigo chamado FilterTaskAuth ,  ele faz a captura da requisição antes da camada de controller,
Ele verifica  se o usuario e senha estão cadastrados no banco de dados e mediante disso faz a autenticação  e manda
os dados da requisição seguir o fluxo para o controller.
## ⚙️ Executando os testes

Explicar como executar os testes automatizados para este sistema.

### 🔩 Entre no insonmia e faça a reqisição   do projeto 

#### Teste cadastro de usuario. post http://localhost:8080/users/

Entrada de dados 
```
{
	"name": "Thiago",
	"username": "magic",
	"password": "123"
}
```
Como usar exemplo na imagem:

* cadusuario
![cadusuario](imagem/postusuario.png)

#### Teste cadastro de tarefa com autenticação. post http://localhost:8080/tasks/

Na aba auth do tipo basic  , informe usuário e senha 
* autenticação

![authusuario](imagem/authtarefa.png)

Volte para o body  e preencha os dados de entrada
Entrada de dados
```
{
	"description": "Tarefa para gravar aula",
	"title": "Gravação de Aula ",
	"priority": "ALTA",
	"startAt": "2023-10-15T18:30:00",
	"endAt": "2023-10-15T21:30:00"
}
```
usar exemplo na imagem:

* cadastro de tarefa
  ![cadtarefa](imagem/posttarefa.png)

#### Teste buscar tarefas com autenticação. GET http://localhost:8080/tasks/

Na aba auth do tipo basic  , informe usuário e senha
* autenticação

![authusuario](imagem/getauth.png)


usar exemplo na imagem:

* buscar tarefa
  ![buscartarefa](imagem/gettarefa.png)



#### Teste atualizar de tarefa com autenticação. put http://localhost:8080/tasks/{passar o id da task que quer atualizar}

Na aba auth do tipo basic  , informe usuário e senha
* autenticação

![authusuario](imagem/authput.png)

Volte para o body  e preencha os dados de entrada
Entrada de dados
```
{
	"title": "Gravação de Aula 2"
}

```
usar exemplo na imagem:

* autualiza tarefa
  ![cadtarefa](imagem/puttarefa.png)
